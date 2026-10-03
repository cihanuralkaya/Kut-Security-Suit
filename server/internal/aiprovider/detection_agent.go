package aiprovider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// DetectionProposal represents a proposed detection rule.
type DetectionProposal struct {
	ID             string
	RuleName       string
	MITRETactic    string
	MITRETechnique string
	Category       string
	Pattern        string
	Severity       string
	Confidence     float64
	Rationale      string
}

// DetectionAgent is responsible for drafting and validating detection rules.
type DetectionAgent struct {
	ragStore    *RAGStore
	modelRouter *ModelRouter
}

// NewDetectionAgent creates a new DetectionAgent instance.
func NewDetectionAgent(rag *RAGStore, router *ModelRouter) *DetectionAgent {
	return &DetectionAgent{
		ragStore:    rag,
		modelRouter: router,
	}
}

// DraftRuleFromHypothesis drafts a declarative detection rule based on a hunt hypothesis and sample signals.
func (a *DetectionAgent) DraftRuleFromHypothesis(ctx context.Context, h HuntHypothesis, sampleSignals []string) (*DetectionProposal, error) {
	if h.ID == "" {
		return nil, errors.New("hypothesis ID cannot be empty")
	}

	// Bu kısımda ModelRouter üzerinden kural oluşturma (LLM) mantığı çalıştırılır.
	// Şimdilik varsayılan/simüle edilmiş bir proposal dönüyoruz.
	proposal := &DetectionProposal{
		ID:             fmt.Sprintf("rule-%s", h.ID),
		RuleName:       fmt.Sprintf("Detect %s", h.Title),
		MITRETactic:    h.MITRETactic,
		MITRETechnique: h.MITRETechnique,
		Category:       "process",
		Pattern:        `.*malicious.*`,
		Severity:       "high",
		Confidence:     0.85,
		Rationale:      "Based on hypothesis: " + h.Description,
	}

	return proposal, nil
}

// ValidateProposal checks a proposal for validity and returns issues.
func (a *DetectionAgent) ValidateProposal(proposal *DetectionProposal) (bool, []string) {
	var issues []string

	if proposal.Pattern == "" {
		issues = append(issues, "pattern is empty")
	} else {
		_, err := regexp.Compile(proposal.Pattern)
		if err != nil {
			issues = append(issues, "invalid regex pattern")
		}
	}

	if !strings.HasPrefix(proposal.MITRETactic, "TA") {
		issues = append(issues, "invalid MITRE tactic format, must start with TA")
	}

	if !strings.HasPrefix(proposal.MITRETechnique, "T") {
		issues = append(issues, "invalid MITRE technique format, must start with T")
	}

	validSeverities := map[string]bool{
		"low":      true,
		"medium":   true,
		"high":     true,
		"critical": true,
	}
	if !validSeverities[strings.ToLower(proposal.Severity)] {
		issues = append(issues, "invalid severity")
	}
	
	if proposal.Confidence < 0.0 || proposal.Confidence > 1.0 {
		issues = append(issues, "confidence must be between 0 and 1")
	}

	return len(issues) == 0, issues
}
