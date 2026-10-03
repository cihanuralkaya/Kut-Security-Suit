package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// DecisionOutcome represents the result of a security decision.
type DecisionOutcome string

const (
	OutcomePermit     DecisionOutcome = "Permit"
	OutcomeDeny       DecisionOutcome = "Deny"
	OutcomeChallenge  DecisionOutcome = "Challenge"
	OutcomeQuarantine DecisionOutcome = "Quarantine"
)

// SecurityContext holds the contextual information for making a decision.
type SecurityContext struct {
	TenantID       string
	ActorID        string
	ActorRole      string
	SourceDeviceID string
	TargetDeviceID string
	ActionName     string
	ActionImpact   string // "read", "write", "destructive"
	RiskScore      float64 // 0.0 to 1.0
	Confidence     float64
}

// SecurityDecision represents an evaluated security decision.
type SecurityDecision struct {
	ID               string
	Context          SecurityContext
	Outcome          DecisionOutcome
	PolicyReason     string
	EvaluatedAt      time.Time
	RequiresDualAuth bool
	AttestationHash  string
}

// DecisionEngine is responsible for evaluating security contexts.
// Kurallar dahilinde bağlamı değerlendirir ve thread-safe çalışır.
type DecisionEngine struct {
	mu sync.RWMutex
}

// NewDecisionEngine creates a new instance of DecisionEngine.
func NewDecisionEngine() *DecisionEngine {
	return &DecisionEngine{}
}

// Evaluate processes a SecurityContext and returns a SecurityDecision.
func (e *DecisionEngine) Evaluate(id string, ctx SecurityContext) SecurityDecision {
	e.mu.Lock()
	defer e.mu.Unlock()

	decision := SecurityDecision{
		ID:          id,
		Context:     ctx,
		EvaluatedAt: time.Now().UTC(),
	}

	// Geçersiz tenant veya kapsam dışı durum kontrolü
	if ctx.TenantID == "" {
		decision.Outcome = OutcomeDeny
		decision.PolicyReason = "Invalid tenant ID"
		decision.AttestationHash = computeAttestationHash(decision)
		return decision
	}

	if ctx.ActionImpact != "read" && ctx.ActionImpact != "write" && ctx.ActionImpact != "destructive" {
		decision.Outcome = OutcomeDeny
		decision.PolicyReason = "Out-of-scope action impact"
		decision.AttestationHash = computeAttestationHash(decision)
		return decision
	}

	// Yüksek riskli yıkıcı eylemler (Destructive action with high risk)
	if ctx.ActionImpact == "destructive" && ctx.RiskScore > 0.7 {
		decision.Outcome = OutcomeChallenge
		decision.RequiresDualAuth = true
		decision.PolicyReason = "High risk destructive action"
	} else if ctx.RiskScore <= 0.3 && (ctx.ActionImpact == "read" || ctx.ActionImpact == "write") {
		// Düşük riskli işlemler (Low risk actions)
		decision.Outcome = OutcomePermit
		decision.PolicyReason = "Low risk action"
	} else {
		// Orta halli senaryolar için varsayılan Karantina davranışı
		decision.Outcome = OutcomeQuarantine
		decision.PolicyReason = "Action requires quarantine for further review"
	}

	// Karar onay karmasını oluştur (Tamper-proof audit trail)
	decision.AttestationHash = computeAttestationHash(decision)
	return decision
}

func computeAttestationHash(d SecurityDecision) string {
	// Canonical representation of context + decision for attestation
	canonical := fmt.Sprintf("%s|%d|%s|%s|%s|%s|%s|%s|%.4f|%.4f|%s|%s|%t",
		d.ID, d.EvaluatedAt.UnixNano(),
		d.Context.TenantID, d.Context.ActorID, d.Context.SourceDeviceID,
		d.Context.TargetDeviceID, d.Context.ActionName, d.Context.ActionImpact,
		d.Context.RiskScore, d.Context.Confidence,
		d.Outcome, d.PolicyReason, d.RequiresDualAuth)
		
	hash := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(hash[:])
}
