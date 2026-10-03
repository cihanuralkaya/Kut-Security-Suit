package telemetryplane

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Alert represents a security alert from an endpoint or service.
type Alert struct {
	ID        string
	TenantID  string
	RuleID    string
	EntityID  string // e.g., device ID or user ID
	Tactic    string // MITRE ATT&CK Tactic
	Technique string
	Severity  string // "low", "medium", "high", "critical"
	Timestamp time.Time
}

// Incident represents a group of correlated alerts.
type Incident struct {
	ID                string
	TenantID          string
	PrimaryEntity     string
	Alerts            []Alert
	TacticsCovered    []string
	CompositeSeverity string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// CorrelationEngine groups alerts and correlates them into incidents.
type CorrelationEngine struct {
	mu             sync.RWMutex
	timeWindow     time.Duration
	incidents      map[string]*Incident // Key: Incident ID
	activeByEntity map[string]string    // Key: TenantID + ":" + EntityID, Value: Incident ID
}

// NewCorrelationEngine creates a new correlation engine with a given time window.
func NewCorrelationEngine(window time.Duration) *CorrelationEngine {
	return &CorrelationEngine{
		timeWindow:     window,
		incidents:      make(map[string]*Incident),
		activeByEntity: make(map[string]string),
	}
}

// IngestAlert processes an incoming alert, groups it into an incident, and escalates severity if needed.
// Returns the incident and a boolean indicating if an escalation occurred.
func (e *CorrelationEngine) IngestAlert(alert Alert) (*Incident, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	entityKey := alert.TenantID + ":" + alert.EntityID
	var incident *Incident
	escalated := false

	incidentID, exists := e.activeByEntity[entityKey]
	if exists {
		incident = e.incidents[incidentID]
		// Check time window expiration
		if alert.Timestamp.Sub(incident.UpdatedAt) > e.timeWindow {
			// Time window expired, start a new incident
			exists = false
		}
	}

	if !exists {
		// Create a new incident
		incidentID = generateID()
		incident = &Incident{
			ID:                incidentID,
			TenantID:          alert.TenantID,
			PrimaryEntity:     alert.EntityID,
			Alerts:            []Alert{},
			TacticsCovered:    []string{},
			CompositeSeverity: alert.Severity,
			CreatedAt:         alert.Timestamp,
			UpdatedAt:         alert.Timestamp,
		}
		e.incidents[incidentID] = incident
		e.activeByEntity[entityKey] = incidentID
	}

	// Add alert to incident
	incident.Alerts = append(incident.Alerts, alert)
	if alert.Timestamp.After(incident.UpdatedAt) {
		incident.UpdatedAt = alert.Timestamp
	}

	// Update tactics
	tacticExists := false
	for _, t := range incident.TacticsCovered {
		if t == alert.Tactic {
			tacticExists = true
			break
		}
	}
	if !tacticExists && alert.Tactic != "" {
		incident.TacticsCovered = append(incident.TacticsCovered, alert.Tactic)
	}

	// Multi-stage progression: 2 or more distinct tactics escalate to critical
	if len(incident.TacticsCovered) >= 2 && incident.CompositeSeverity != "critical" {
		incident.CompositeSeverity = "critical"
		escalated = true
	} else if incident.CompositeSeverity != "critical" {
		// Update composite severity to highest alert severity if not critical
		incident.CompositeSeverity = highestSeverity(incident.CompositeSeverity, alert.Severity)
	}

	return incident, escalated
}

// GetIncidents returns all incidents for a specific tenant.
func (e *CorrelationEngine) GetIncidents(tenantID string) []*Incident {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []*Incident
	for _, incident := range e.incidents {
		if incident.TenantID == tenantID {
			result = append(result, incident)
		}
	}
	return result
}

// highestSeverity returns the highest of two severities
func highestSeverity(s1, s2 string) string {
	severities := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	if severities[s2] > severities[s1] {
		return s2
	}
	return s1
}

func generateID() string {
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
