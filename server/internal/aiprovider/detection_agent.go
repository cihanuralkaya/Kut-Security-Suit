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

	// Deterministik taslak: örnek sinyallerden GERÇEKTEN eşleşen bir regex türetilir
	// (eski `.*malicious.*` yer-tutucusu örnekleri yok sayıyordu — aktivasyon-bulgusu).
	// ADVISORY: taslak kurala DÖNÜŞMEZ; analist inceler/ince-ayar yapar (DRAFT).
	pattern := patternFromSignals(sampleSignals)
	if pattern == "" {
		pattern = `(?i)` + regexp.QuoteMeta(strings.TrimSpace(h.MITRETechnique)) // geri-düşüş: teknik imzası
	}
	proposal := &DetectionProposal{
		ID:             fmt.Sprintf("rule-%s", h.ID),
		RuleName:       fmt.Sprintf("Detect %s", h.Title),
		MITRETactic:    h.MITRETactic,
		MITRETechnique: h.MITRETechnique,
		Category:       "", // kategori-bağımsız (detect message-regex deseni)
		Pattern:        pattern,
		Severity:       "high",
		Confidence:     0.6, // deterministik taslak: orta güven (analist doğrulamalı)
		Rationale:      fmt.Sprintf("%d örnek sinyalden türetildi; hipotez: %s", len(sampleSignals), h.Description),
	}

	return proposal, nil
}

// patternFromSignals, örnek sinyallerden deterministik bir regex türetir: TÜM örneklerde
// ortak, ayırt edici (len>=4) token'ları İLK örnekteki SIRAYLA .* ile bağlar (sıra korunur
// → üretilen desen örnekleri gerçekten eşler). Örnek yoksa boş döner.
func patternFromSignals(samples []string) string {
	if len(samples) == 0 {
		return ""
	}
	common := tokenSet(samples[0])
	for _, s := range samples[1:] {
		ts := tokenSet(s)
		for t := range common {
			if !ts[t] {
				delete(common, t)
			}
		}
	}
	var ordered []string
	added := map[string]bool{}
	for _, raw := range strings.Fields(samples[0]) {
		t := strings.ToLower(raw)
		if len(t) >= 4 && common[t] && !added[t] {
			ordered = append(ordered, t)
			added[t] = true
		}
	}
	if len(ordered) == 0 {
		return ""
	}
	esc := make([]string, len(ordered))
	for i, t := range ordered {
		esc[i] = regexp.QuoteMeta(t)
	}
	return `(?i)` + strings.Join(esc, ".*")
}

func tokenSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, f := range strings.Fields(strings.ToLower(s)) {
		m[f] = true
	}
	return m
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
