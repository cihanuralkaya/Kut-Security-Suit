package telemetryplane

import (
	"testing"
	"time"
)

func TestIngestAlert_SingleAlert(t *testing.T) {
	engine := NewCorrelationEngine(1 * time.Hour)
	alert := Alert{
		ID:        "a1",
		TenantID:  "tenant1",
		RuleID:    "rule1",
		EntityID:  "device1",
		Tactic:    "Initial Access",
		Technique: "Phishing",
		Severity:  "medium",
		Timestamp: time.Now(),
	}

	incident, escalated := engine.IngestAlert(alert)

	if escalated {
		t.Errorf("Expected no escalation for single alert")
	}
	if incident == nil {
		t.Fatalf("Expected incident to be created")
	}
	if incident.CompositeSeverity != "medium" {
		t.Errorf("Expected severity 'medium', got '%s'", incident.CompositeSeverity)
	}
	if len(incident.Alerts) != 1 {
		t.Errorf("Expected 1 alert in incident, got %d", len(incident.Alerts))
	}
}

func TestIngestAlert_MultiStageProgression(t *testing.T) {
	engine := NewCorrelationEngine(1 * time.Hour)
	now := time.Now()

	alert1 := Alert{
		ID:        "a1",
		TenantID:  "tenant1",
		EntityID:  "user1",
		Tactic:    "Initial Access",
		Severity:  "medium",
		Timestamp: now,
	}

	alert2 := Alert{
		ID:        "a2",
		TenantID:  "tenant1",
		EntityID:  "user1",
		Tactic:    "Execution",
		Severity:  "high",
		Timestamp: now.Add(5 * time.Minute),
	}

	incident, escalated1 := engine.IngestAlert(alert1)
	if escalated1 {
		t.Errorf("Expected no escalation on first alert")
	}

	incident, escalated2 := engine.IngestAlert(alert2)
	if !escalated2 {
		t.Errorf("Expected escalation on second alert with different tactic")
	}
	if incident.CompositeSeverity != "critical" {
		t.Errorf("Expected severity 'critical', got '%s'", incident.CompositeSeverity)
	}
	if len(incident.TacticsCovered) != 2 {
		t.Errorf("Expected 2 tactics covered, got %d", len(incident.TacticsCovered))
	}
}

func TestIngestAlert_TenantIsolation(t *testing.T) {
	engine := NewCorrelationEngine(1 * time.Hour)
	now := time.Now()

	alert1 := Alert{
		TenantID:  "tenant1",
		EntityID:  "device1",
		Tactic:    "Initial Access",
		Severity:  "low",
		Timestamp: now,
	}
	alert2 := Alert{
		TenantID:  "tenant2",
		EntityID:  "device1", // Same entity ID, different tenant
		Tactic:    "Execution",
		Severity:  "low",
		Timestamp: now.Add(5 * time.Minute),
	}

	engine.IngestAlert(alert1)
	engine.IngestAlert(alert2)

	incidentsT1 := engine.GetIncidents("tenant1")
	incidentsT2 := engine.GetIncidents("tenant2")

	if len(incidentsT1) != 1 {
		t.Errorf("Expected 1 incident for tenant1, got %d", len(incidentsT1))
	}
	if len(incidentsT2) != 1 {
		t.Errorf("Expected 1 incident for tenant2, got %d", len(incidentsT2))
	}
	if incidentsT1[0].CompositeSeverity == "critical" || incidentsT2[0].CompositeSeverity == "critical" {
		t.Errorf("Expected no escalation due to tenant isolation")
	}
}

func TestIngestAlert_WindowExpiration(t *testing.T) {
	engine := NewCorrelationEngine(1 * time.Hour)
	now := time.Now()

	alert1 := Alert{
		TenantID:  "tenant1",
		EntityID:  "device1",
		Tactic:    "Initial Access",
		Timestamp: now,
	}
	// Outside the 1-hour window
	alert2 := Alert{
		TenantID:  "tenant1",
		EntityID:  "device1",
		Tactic:    "Execution",
		Timestamp: now.Add(2 * time.Hour),
	}

	incident1, _ := engine.IngestAlert(alert1)
	incident2, _ := engine.IngestAlert(alert2)

	if incident1.ID == incident2.ID {
		t.Errorf("Expected separate incidents due to window expiration")
	}
}
