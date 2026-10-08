package telemetryplane

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"kut.corp/suite/server/internal/model"
)

// RuleCondition represents a single condition within a rule.
type RuleCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// Rule represents a detection rule.
type Rule struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Severity       string          `json:"severity"`
	Category       string          `json:"category"`
	MITRETactic    string          `json:"mitre_tactic"`
	MITRETechnique string          `json:"mitre_technique"`
	Conditions     []RuleCondition `json:"conditions"`
	Enabled        bool            `json:"enabled"`
}

// RuleEngine evaluates events against a set of rules.
type RuleEngine struct {
	mu    sync.RWMutex
	rules []Rule
}

// NewRuleEngine creates a new RuleEngine.
func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		rules: make([]Rule, 0),
	}
}

// AddRule adds a new rule to the engine.
func (re *RuleEngine) AddRule(r Rule) error {
	re.mu.Lock()
	defer re.mu.Unlock()
	re.rules = append(re.rules, r)
	return nil
}

// LoadRulesFromJSON loads rules from a JSON byte array.
func (re *RuleEngine) LoadRulesFromJSON(data []byte) error {
	var rules []Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("kural JSON ayrıştırma hatası: %w", err)
	}

	re.mu.Lock()
	defer re.mu.Unlock()
	for _, r := range rules {
		re.rules = append(re.rules, r)
	}
	return nil
}

// Evaluate checks an event against all enabled rules and returns the matched rules.
func (re *RuleEngine) Evaluate(evt model.Event) (matched []Rule) {
	re.mu.RLock()
	defer re.mu.RUnlock()

	for _, rule := range re.rules {
		if !rule.Enabled {
			continue
		}
		if re.evaluateRule(rule, evt) {
			matched = append(matched, rule)
		}
	}
	return
}

func (re *RuleEngine) evaluateRule(rule Rule, evt model.Event) bool {
	if len(rule.Conditions) == 0 {
		return false
	}

	// Tüm koşulların sağlanması gerekir (AND mantığı)
	for _, cond := range rule.Conditions {
		if !re.evaluateCondition(cond, evt) {
			return false
		}
	}
	return true
}

func (re *RuleEngine) evaluateCondition(cond RuleCondition, evt model.Event) bool {
	val := getFieldValue(cond.Field, evt)

	switch cond.Operator {
	case "equals":
		return val == cond.Value
	case "contains":
		return strings.Contains(val, cond.Value)
	case "prefix":
		return strings.HasPrefix(val, cond.Value)
	case "regex":
		matched, err := regexp.MatchString(cond.Value, val)
		if err != nil {
			return false
		}
		return matched
	default:
		return false
	}
}

func getFieldValue(field string, evt model.Event) string {
	switch field {
	case "category":
		return evt.Category
	case "source":
		return evt.Source
	case "message":
		return evt.Message
	case "event_type":
		return evt.EventType
	case "severity":
		return evt.Severity
	default:
		return ""
	}
}
