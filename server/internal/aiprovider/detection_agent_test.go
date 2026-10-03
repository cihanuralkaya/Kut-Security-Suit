package aiprovider

import (
	"context"
	"testing"
)

func TestDraftRuleFromHypothesis(t *testing.T) {
	agent := NewDetectionAgent(nil, nil)

	h := HuntHypothesis{
		ID:             "hyp-1",
		Title:          "Suspicious PowerShell Execution",
		MITRETactic:    "TA0002",
		MITRETechnique: "T1059",
		Description:    "Execution of base64 encoded powershell commands",
	}

	ctx := context.Background()
	proposal, err := agent.DraftRuleFromHypothesis(ctx, h, []string{"powershell.exe -enc"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proposal == nil {
		t.Fatal("proposal should not be nil")
	}
	if proposal.ID != "rule-hyp-1" {
		t.Errorf("expected rule-hyp-1, got %s", proposal.ID)
	}
	if proposal.MITRETactic != "TA0002" {
		t.Errorf("expected TA0002, got %s", proposal.MITRETactic)
	}
	if proposal.MITRETechnique != "T1059" {
		t.Errorf("expected T1059, got %s", proposal.MITRETechnique)
	}
}

func TestValidateProposal_Valid(t *testing.T) {
	agent := NewDetectionAgent(nil, nil)
	proposal := &DetectionProposal{
		Pattern:        `^powershell\.exe -enc.*`,
		MITRETactic:    "TA0002",
		MITRETechnique: "T1059.001",
		Severity:       "High",
		Confidence:     0.9,
	}

	valid, issues := agent.ValidateProposal(proposal)
	if !valid {
		t.Errorf("expected valid, got issues: %v", issues)
	}
}

func TestValidateProposal_Invalid(t *testing.T) {
	agent := NewDetectionAgent(nil, nil)
	proposal := &DetectionProposal{
		Pattern:        `[`,         // Invalid regex
		MITRETactic:    "Execution", // Invalid format, missing TA
		MITRETechnique: "1059",      // Invalid format, missing T
		Severity:       "unknown",   // Invalid severity
		Confidence:     1.5,         // Invalid confidence
	}

	valid, issues := agent.ValidateProposal(proposal)
	if valid {
		t.Error("expected invalid, but got valid")
	}
	if len(issues) != 5 {
		t.Errorf("expected 5 issues, got %d: %v", len(issues), issues)
	}
}
