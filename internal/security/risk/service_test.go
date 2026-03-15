package risk

import (
	"testing"
	"time"
)

func TestAnalyzeHighRiskBurst(t *testing.T) {
	service := NewService()
	base := time.Date(2026, 2, 24, 12, 0, 0, 0, time.UTC)

	var last AnalyzeResult
	for i := 0; i < 80; i++ {
		result, err := service.Analyze(AnalyzeInput{
			IP:        "203.0.113.10",
			Path:      "/login",
			UserAgent: "bot/1.0",
			Timestamp: base.Add(time.Duration(i) * 100 * time.Millisecond),
		})
		if err != nil {
			t.Fatalf("analyze: %v", err)
		}
		last = result
	}

	if last.RiskLevel != "high" {
		t.Fatalf("expected high risk level, got %q", last.RiskLevel)
	}
	if last.BotProbability < 60 {
		t.Fatalf("expected bot probability >= 60, got %f", last.BotProbability)
	}
}

func TestAnalyzeInvalidIP(t *testing.T) {
	service := NewService()
	_, err := service.Analyze(AnalyzeInput{
		IP: "not-an-ip",
	})
	if err == nil {
		t.Fatalf("expected invalid ip error")
	}
}
