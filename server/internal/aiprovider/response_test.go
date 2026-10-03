package aiprovider

import (
	"context"
	"testing"

	"kut.corp/suite/server/internal/entitygraph"
)

func TestProposePlan(t *testing.T) {
	agent := NewResponseAgent(nil, nil)
	ctx := context.Background()

	tenantID := "tenant-1"
	incidentID := "inc-100"
	severity := "Critical"
	
	node := entitygraph.Node{
		ID:   "node-1",
		Kind: "Process",
	}

	findings := []HuntFinding{
		{
			HypothesisID: "hyp-1",
			TargetNode:   node,
		},
		{
			HypothesisID: "hyp-2",
			TargetNode:   node,
		},
	}

	plan, err := agent.ProposePlan(ctx, tenantID, incidentID, findings, severity)
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}

	if plan.IncidentID != incidentID {
		t.Errorf("beklenen incidentID %s, alınan %s", incidentID, plan.IncidentID)
	}

	if plan.TenantID != tenantID {
		t.Errorf("beklenen tenantID %s, alınan %s", tenantID, plan.TenantID)
	}

	if len(plan.Actions) != 2 {
		t.Fatalf("beklenen aksiyon sayısı 2, alınan %d", len(plan.Actions))
	}

	for _, action := range plan.Actions {
		if action.TenantID != tenantID {
			t.Errorf("aksiyonda beklenen tenantID %s, alınan %s", tenantID, action.TenantID)
		}
		
		// Critical senaryoda aksiyonların destructive olması ve onay gerektirmesi beklenir
		if !action.RequiresApproval {
			t.Errorf("Critical seviyede aksiyon onay gerektirmeli")
		}
	}
}

func TestProposePlan_Validation(t *testing.T) {
	agent := NewResponseAgent(nil, nil)
	ctx := context.Background()

	_, err := agent.ProposePlan(ctx, "", "inc-1", nil, "Low")
	if err == nil {
		t.Error("boş tenantID ile hata bekleniyordu")
	}

	_, err = agent.ProposePlan(ctx, "tenant-1", "", nil, "Low")
	if err == nil {
		t.Error("boş incidentID ile hata bekleniyordu")
	}
}

func TestExecuteAction_NonDestructive(t *testing.T) {
	agent := NewResponseAgent(nil, nil)
	ctx := context.Background()

	action := &ResponseAction{
		ID:               "act-1",
		Type:             ActionBlockHash,
		TenantID:         "tenant-1",
		RequiresApproval: false,
		Approved:         false,
	}

	err := agent.ExecuteAction(ctx, action, "")
	if err != nil {
		t.Fatalf("non-destructive aksiyon için hata beklenmiyordu: %v", err)
	}

	if action.ExecutedAt.IsZero() {
		t.Error("aksiyonun executed_at alanı güncellenmeliydi")
	}
}

func TestExecuteAction_DestructiveWithoutApproval(t *testing.T) {
	agent := NewResponseAgent(nil, nil)
	ctx := context.Background()

	action := &ResponseAction{
		ID:               "act-1",
		Type:             ActionIsolateEndpoint,
		TenantID:         "tenant-1",
		RequiresApproval: true,
		Approved:         false,
	}

	err := agent.ExecuteAction(ctx, action, "")
	if err == nil {
		t.Fatal("onaylanmamış destructive aksiyon için hata bekleniyordu")
	}
}

func TestExecuteAction_DestructiveWithApproval(t *testing.T) {
	agent := NewResponseAgent(nil, nil)
	ctx := context.Background()

	action := &ResponseAction{
		ID:               "act-1",
		Type:             ActionIsolateEndpoint,
		TenantID:         "tenant-1",
		RequiresApproval: true,
		Approved:         false,
	}

	err := agent.ExecuteAction(ctx, action, "admin-user")
	if err != nil {
		t.Fatalf("onaylanmış destructive aksiyon için hata beklenmiyordu: %v", err)
	}

	if !action.Approved {
		t.Error("aksiyon approved olarak işaretlenmeliydi")
	}

	if action.ExecutedAt.IsZero() {
		t.Error("aksiyonun executed_at alanı güncellenmeliydi")
	}
}
