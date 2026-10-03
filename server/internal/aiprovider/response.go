package aiprovider

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ResponseActionType e.g. "IsolateEndpoint", "BlockHash", "RevokeSession", "QuarantineFile", "KillProcess"
type ResponseActionType string

const (
	ActionIsolateEndpoint ResponseActionType = "IsolateEndpoint"
	ActionBlockHash       ResponseActionType = "BlockHash"
	ActionRevokeSession   ResponseActionType = "RevokeSession"
	ActionQuarantineFile  ResponseActionType = "QuarantineFile"
	ActionKillProcess     ResponseActionType = "KillProcess"
)

// ResponseAction represents a specific remediation action to be taken.
type ResponseAction struct {
	ID               string             `json:"id"`
	Type             ResponseActionType `json:"type"`
	Target           string             `json:"target"`
	TenantID         string             `json:"tenant_id"`
	RequiresApproval bool               `json:"requires_approval"`
	Reason           string             `json:"reason"`
	Approved         bool               `json:"approved"`
	ExecutedAt       time.Time          `json:"executed_at,omitempty"`
}

// ResponsePlan groups multiple actions into a single coordinated response plan.
type ResponsePlan struct {
	IncidentID  string           `json:"incident_id"`
	TenantID    string           `json:"tenant_id"`
	Actions     []ResponseAction `json:"actions"`
	GeneratedAt time.Time        `json:"generated_at"`
}

// ResponseAgent is responsible for evaluating findings and executing remediation actions.
type ResponseAgent struct {
	ModelRouter *ModelRouter
	RAGStore    *RAGStore
}

// NewResponseAgent creates a new autonomous response agent.
func NewResponseAgent(router *ModelRouter, ragStore *RAGStore) *ResponseAgent {
	return &ResponseAgent{
		ModelRouter: router,
		RAGStore:    ragStore,
	}
}

// ProposePlan evaluates severity and findings.
// Generates structured remediation plan. If severity is Critical, flags immediate containment actions.
// If action is destructive, sets RequiresApproval = true.
func (a *ResponseAgent) ProposePlan(ctx context.Context, tenantID string, incidentID string, findings []HuntFinding, severity string) (*ResponsePlan, error) {
	if tenantID == "" || incidentID == "" {
		return nil, errors.New("tenantID and incidentID are required")
	}

	plan := &ResponsePlan{
		IncidentID:  incidentID,
		TenantID:    tenantID,
		GeneratedAt: time.Now().UTC(),
		Actions:     make([]ResponseAction, 0),
	}

	for i, f := range findings {
		actionType := ActionBlockHash
		requiresApproval := false

		// Eğer severity Critical ise, immediate containment action'ları belirle.
		if severity == "Critical" {
			if i%2 == 0 {
				actionType = ActionIsolateEndpoint
			} else {
				actionType = ActionKillProcess
			}
		} else if severity == "High" {
			actionType = ActionQuarantineFile
		}

		// Destructive action'lar onay gerektirir.
		if actionType == ActionIsolateEndpoint || actionType == ActionKillProcess || actionType == ActionQuarantineFile {
			requiresApproval = true
		}

		// Target olarak bulgunun özetini veya varsa ilgili ID'yi alıyoruz.
		target := fmt.Sprintf("%v", f.TargetNode)

		actionID := fmt.Sprintf("action-%s-%d", incidentID, i)
		plan.Actions = append(plan.Actions, ResponseAction{
			ID:               actionID,
			Type:             actionType,
			Target:           target,
			TenantID:         tenantID,
			RequiresApproval: requiresApproval,
			Reason:           fmt.Sprintf("Auto-generated mitigation for finding (Hypothesis: %s)", f.HypothesisID),
			Approved:         false,
		})
	}

	return plan, nil
}

// ExecuteAction executes a specific response action.
// If RequiresApproval is true and Approved is false, returns error unless valid approver is provided.
// Marks Approved = true, records execution.
func (a *ResponseAgent) ExecuteAction(ctx context.Context, action *ResponseAction, approver string) error {
	if action == nil {
		return errors.New("action is nil")
	}

	if action.RequiresApproval {
		if !action.Approved && approver == "" {
			return errors.New("action requires approval")
		}
		if approver != "" {
			action.Approved = true
		}
	}

	// Aksiyon simülasyonu
	action.ExecutedAt = time.Now().UTC()

	return nil
}
