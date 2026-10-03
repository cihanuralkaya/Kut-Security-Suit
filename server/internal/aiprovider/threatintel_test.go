package aiprovider

import (
	"sync"
	"testing"
	"time"
)

func TestIngestAndEnrich(t *testing.T) {
	agent := NewThreatIntelAgent()

	indicator := ThreatIndicator{
		Value:           "1.1.1.1",
		Type:            IOCTypeIPv4,
		ThreatActor:     "APT29",
		MalwareFamily:   "CobaltStrike",
		ConfidenceScore: 0.85,
		FirstSeen:       time.Now().Add(-24 * time.Hour),
		LastSeen:        time.Now(),
		Tags:            []string{"c2", "malicious"},
	}

	err := agent.IngestIndicator(indicator)
	if err != nil {
		t.Fatalf("Failed to ingest indicator: %v", err)
	}

	result := agent.EnrichIOC("1.1.1.1", IOCTypeIPv4)
	if !result.IsKnownMalicious {
		t.Errorf("Expected indicator to be known malicious")
	}
	if result.ReputationScore != 0.85 {
		t.Errorf("Expected reputation score 0.85, got %v", result.ReputationScore)
	}
	if len(result.MatchedActors) == 0 || result.MatchedActors[0] != "APT29" {
		t.Errorf("Expected MatchedActors to contain APT29")
	}
	if len(result.MatchedFamilies) == 0 || result.MatchedFamilies[0] != "CobaltStrike" {
		t.Errorf("Expected MatchedFamilies to contain CobaltStrike")
	}

	// Test benign/unknown IOC
	resultBenign := agent.EnrichIOC("8.8.8.8", IOCTypeIPv4)
	if resultBenign.IsKnownMalicious {
		t.Errorf("Expected 8.8.8.8 to be benign")
	}
	if resultBenign.ReputationScore != 0 {
		t.Errorf("Expected reputation score 0 for unknown IOC, got %v", resultBenign.ReputationScore)
	}
}

func TestBulkEnrich(t *testing.T) {
	agent := NewThreatIntelAgent()

	agent.IngestIndicator(ThreatIndicator{Value: "malicious.com", ConfidenceScore: 0.9, ThreatActor: "APT-1"})
	agent.IngestIndicator(ThreatIndicator{Value: "bad-ip", ConfidenceScore: 0.75, MalwareFamily: "RansomwareX"})

	iocs := []string{"malicious.com", "unknown.com", "bad-ip"}
	results := agent.BulkEnrich(iocs)

	if len(results) != 3 {
		t.Fatalf("Expected 3 results, got %v", len(results))
	}

	if results[0].Indicator != "malicious.com" || !results[0].IsKnownMalicious {
		t.Errorf("Expected malicious.com to be malicious")
	}
	if results[1].Indicator != "unknown.com" || results[1].IsKnownMalicious {
		t.Errorf("Expected unknown.com to be unknown/benign")
	}
	if results[2].Indicator != "bad-ip" || !results[2].IsKnownMalicious {
		t.Errorf("Expected bad-ip to be malicious")
	}
}

func TestThreadSafety(t *testing.T) {
	agent := NewThreatIntelAgent()
	var wg sync.WaitGroup

	numGoroutines := 100
	wg.Add(numGoroutines * 2)

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		go func(val int) {
			defer wg.Done()
			agent.IngestIndicator(ThreatIndicator{
				Value:           "test-indicator",
				ConfidenceScore: 0.9,
			})
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			agent.EnrichIOC("test-indicator", "")
		}()
	}

	wg.Wait()
}
