package aiprovider

import (
	"context"
	"regexp"
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

// TestDraftRule_PatternDerivedFromSignals, taslak desenin örnek sinyalleri GERÇEKTEN
// eşlediğini + zararsız metni eşlemediğini doğrular (aktivasyon-iyileştirmesi: eski
// `.*malicious.*` yer-tutucusu örnekleri yok sayıyordu).
func TestDraftRule_PatternDerivedFromSignals(t *testing.T) {
	agent := NewDetectionAgent(nil, nil)
	h := HuntHypothesis{ID: "h9", Title: "encoded ps", MITRETactic: "TA0002", MITRETechnique: "T1059"}
	p, err := agent.DraftRuleFromHypothesis(context.Background(), h,
		[]string{"powershell.exe -enc AAAA", "powershell.exe -enc BBBB"})
	if err != nil {
		t.Fatal(err)
	}
	if ok, issues := agent.ValidateProposal(p); !ok {
		t.Fatalf("türetilen taslak geçerli olmalı (TA0002/T1059/regex): %v", issues)
	}
	re := regexp.MustCompile(p.Pattern)
	if !re.MatchString("powershell.exe -enc AAAA") {
		t.Errorf("türetilen desen örnek sinyali eşlemeli, desen=%q", p.Pattern)
	}
	if re.MatchString("notepad.exe opened document") {
		t.Errorf("türetilen desen zararsız metni eşlememeli, desen=%q", p.Pattern)
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
