package telemetryplane

import (
	"context"
	"testing"

	"kut.corp/suite/server/internal/model"
	"kut.corp/suite/server/internal/telemetryschema"
)

func TestRuleEngine_Evaluate(t *testing.T) {
	re := NewRuleEngine()

	err := re.AddRule(Rule{
		ID:             "rule-1",
		Name:           "Test Category Rule",
		Severity:       "HIGH",
		Category:       "Process",
		MITRETechnique: "T1059",
		Enabled:        true,
		Conditions: []RuleCondition{
			{Field: "category", Operator: "equals", Value: "Process"},
			{Field: "message", Operator: "contains", Value: "cmd.exe"},
		},
	})
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	err = re.AddRule(Rule{
		ID:             "rule-2",
		Name:           "Regex Rule",
		Severity:       "CRITICAL",
		Category:       "Network",
		MITRETechnique: "T1043",
		Enabled:        true,
		Conditions: []RuleCondition{
			{Field: "source", Operator: "equals", Value: "endpoint"},
			{Field: "message", Operator: "regex", Value: `^Suspicious connection to \d{1,3}(\.\d{1,3}){3}$`},
		},
	})
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	tests := []struct {
		name          string
		event         model.Event
		expectedCount int
		expectedIDs   []string
	}{
		{
			name: "Match Process Rule",
			event: model.Event{
				Category: "Process",
				Message:  "Execution of cmd.exe detected",
			},
			expectedCount: 1,
			expectedIDs:   []string{"rule-1"},
		},
		{
			name: "No Match - Different Category",
			event: model.Event{
				Category: "File",
				Message:  "Execution of cmd.exe detected",
			},
			expectedCount: 0,
			expectedIDs:   nil,
		},
		{
			name: "Match Regex Rule",
			event: model.Event{
				Category: "Network",
				Source:   "endpoint",
				Message:  "Suspicious connection to 192.168.1.100",
			},
			expectedCount: 1,
			expectedIDs:   []string{"rule-2"},
		},
		{
			name: "No Match Regex - Bad Message",
			event: model.Event{
				Category: "Network",
				Source:   "endpoint",
				Message:  "Suspicious connection to example.com",
			},
			expectedCount: 0,
			expectedIDs:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := re.Evaluate(tt.event)
			if len(matched) != tt.expectedCount {
				t.Errorf("Evaluate() matched %d rules; want %d", len(matched), tt.expectedCount)
			}

			// Validate matched IDs
			if tt.expectedCount > 0 {
				found := false
				for _, r := range matched {
					for _, expID := range tt.expectedIDs {
						if r.ID == expID {
							found = true
							break
						}
					}
				}
				if !found {
					t.Errorf("Evaluate() did not match expected rules. Got: %v", matched)
				}
			}
		})
	}
}

func TestRuleEngine_LoadRulesFromJSON(t *testing.T) {
	jsonData := []byte(`[
		{
			"id": "rule-3",
			"name": "JSON Loaded Rule",
			"severity": "LOW",
			"category": "Auth",
			"enabled": true,
			"conditions": [
				{ "field": "category", "operator": "equals", "value": "Auth" }
			]
		}
	]`)

	re := NewRuleEngine()
	err := re.LoadRulesFromJSON(jsonData)
	if err != nil {
		t.Fatalf("LoadRulesFromJSON failed: %v", err)
	}

	matched := re.Evaluate(model.Event{
		Category: "Auth",
	})
	if len(matched) != 1 || matched[0].ID != "rule-3" {
		t.Errorf("Expected to match loaded rule, got: %v", matched)
	}
}

// Mock AlertSink and EventSink for Plane testing
type mockSink struct{}

func (s *mockSink) EmitAlert(ctx context.Context, evt telemetryschema.Event) error { return nil }
func (s *mockSink) EmitEvent(ctx context.Context, evt telemetryschema.Event) error { return nil }

func TestRuleEngine_PlaneIntegration(t *testing.T) {
	re := NewRuleEngine()
	re.AddRule(Rule{
		ID:      "rule-plane",
		Enabled: true,
		Conditions: []RuleCondition{
			{Field: "category", Operator: "equals", Value: "TestCategory"},
		},
	})

	sink := &mockSink{}
	plane := New(re, sink, sink)

	ctx := context.Background()
	plane.Start(ctx)
	defer plane.Stop()

	evt := model.Event{
		Category: "TestCategory",
		Message:  "Trigger Alert",
	}

	// This should process successfully and theoretically trigger the alert sink (although we mock it)
	_, err := plane.ProcessEvent(ctx, evt)
	if err != nil {
		t.Fatalf("ProcessEvent failed: %v", err)
	}
}
