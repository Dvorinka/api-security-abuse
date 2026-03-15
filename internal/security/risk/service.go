package risk

import (
	"errors"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

type Service struct {
	mu     sync.Mutex
	events map[string][]event
}

type event struct {
	Timestamp time.Time
	Path      string
	UserAgent string
}

type AnalyzeInput struct {
	IP        string    `json:"ip"`
	Path      string    `json:"path"`
	UserAgent string    `json:"user_agent"`
	Timestamp time.Time `json:"timestamp,omitempty"`
}

type AnalyzeResult struct {
	IP                 string  `json:"ip"`
	RequestCount1m     int     `json:"request_count_1m"`
	RequestCount5m     int     `json:"request_count_5m"`
	UniquePaths5m      int     `json:"unique_paths_5m"`
	UniqueUserAgents5m int     `json:"unique_user_agents_5m"`
	AverageIntervalMS  float64 `json:"average_interval_ms"`
	BurstScore         float64 `json:"burst_score"`
	BotProbability     float64 `json:"bot_probability"`
	AbuseLikelihood    float64 `json:"abuse_likelihood"`
	RiskScore          int     `json:"risk_score"`
	RiskLevel          string  `json:"risk_level"`
	RecommendedAction  string  `json:"recommended_action"`
}

func NewService() *Service {
	return &Service{
		events: make(map[string][]event),
	}
}

func (s *Service) Analyze(input AnalyzeInput) (AnalyzeResult, error) {
	ip := strings.TrimSpace(input.IP)
	if ip == "" {
		return AnalyzeResult{}, errors.New("ip is required")
	}
	if parsed := net.ParseIP(ip); parsed == nil {
		return AnalyzeResult{}, errors.New("invalid ip")
	}

	now := input.Timestamp.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	path := strings.TrimSpace(input.Path)
	if path == "" {
		path = "/"
	}
	userAgent := strings.TrimSpace(input.UserAgent)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanup(ip, now)
	s.events[ip] = append(s.events[ip], event{
		Timestamp: now,
		Path:      path,
		UserAgent: userAgent,
	})

	events := s.events[ip]
	window1m := now.Add(-1 * time.Minute)
	window5m := now.Add(-5 * time.Minute)

	count1m := 0
	count5m := 0
	paths := map[string]struct{}{}
	userAgents := map[string]struct{}{}
	timestamps := make([]time.Time, 0, len(events))

	for _, ev := range events {
		if ev.Timestamp.After(window1m) {
			count1m++
		}
		if ev.Timestamp.After(window5m) {
			count5m++
			paths[ev.Path] = struct{}{}
			if ev.UserAgent != "" {
				userAgents[ev.UserAgent] = struct{}{}
			}
			timestamps = append(timestamps, ev.Timestamp)
		}
	}

	avgInterval := averageIntervalMS(timestamps)
	burstScore := burstScore(count1m, avgInterval)
	botProbability := botProbability(count1m, len(paths), len(userAgents), avgInterval)
	abuseLikelihood := abuseLikelihood(count1m, count5m, burstScore, botProbability)
	riskScore, riskLevel, action := riskClassification(botProbability, abuseLikelihood)

	return AnalyzeResult{
		IP:                 ip,
		RequestCount1m:     count1m,
		RequestCount5m:     count5m,
		UniquePaths5m:      len(paths),
		UniqueUserAgents5m: len(userAgents),
		AverageIntervalMS:  round2(avgInterval),
		BurstScore:         round2(burstScore),
		BotProbability:     round2(botProbability),
		AbuseLikelihood:    round2(abuseLikelihood),
		RiskScore:          riskScore,
		RiskLevel:          riskLevel,
		RecommendedAction:  action,
	}, nil
}

func (s *Service) cleanup(ip string, now time.Time) {
	events := s.events[ip]
	if len(events) == 0 {
		return
	}
	cutoff := now.Add(-10 * time.Minute)
	idx := 0
	for idx < len(events) && events[idx].Timestamp.Before(cutoff) {
		idx++
	}
	if idx > 0 {
		events = events[idx:]
	}
	if len(events) == 0 {
		delete(s.events, ip)
		return
	}
	s.events[ip] = events
}

func averageIntervalMS(times []time.Time) float64 {
	if len(times) < 2 {
		return 0
	}
	sort.Slice(times, func(i, j int) bool {
		return times[i].Before(times[j])
	})

	var total float64
	for i := 1; i < len(times); i++ {
		total += times[i].Sub(times[i-1]).Seconds() * 1000
	}
	return total / float64(len(times)-1)
}

func burstScore(count1m int, avgIntervalMS float64) float64 {
	base := float64(count1m) / 2
	if avgIntervalMS > 0 {
		base += math.Max(0, (500-avgIntervalMS)/25)
	}
	if base > 100 {
		base = 100
	}
	return base
}

func botProbability(count1m, uniquePaths, uniqueUserAgents int, avgIntervalMS float64) float64 {
	score := 0.0
	if count1m > 30 {
		score += 40
	} else if count1m > 15 {
		score += 20
	}
	if uniquePaths <= 2 && count1m >= 10 {
		score += 20
	}
	if uniqueUserAgents <= 1 && count1m >= 10 {
		score += 20
	}
	if avgIntervalMS > 0 && avgIntervalMS < 300 {
		score += 20
	}
	if score > 100 {
		score = 100
	}
	return score
}

func abuseLikelihood(count1m, count5m int, burstScore, botProbability float64) float64 {
	score := 0.0
	score += botProbability * 0.5
	score += burstScore * 0.3
	if count5m > 100 {
		score += 20
	}
	if count1m > 40 {
		score += 20
	}
	if score > 100 {
		score = 100
	}
	return score
}

func riskClassification(botProbability, abuseLikelihood float64) (score int, level, action string) {
	raw := (botProbability*0.4 + abuseLikelihood*0.6)
	if raw > 100 {
		raw = 100
	}
	score = int(math.Round(raw))
	switch {
	case score >= 75:
		return score, "high", "block_or_challenge"
	case score >= 45:
		return score, "medium", "rate_limit"
	default:
		return score, "low", "allow"
	}
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}
