package coordinator

import (
	"context"
	"errors"
	"testing"
	"time"
)

// allowAllFaultAuthz grants every fault injection; used by lifecycle tests that
// are not exercising the authorization gate itself.
type allowAllFaultAuthz struct{}

func (allowAllFaultAuthz) AuthorizeFault(ctx context.Context, actor string, fault ChaosFaultType, target string) error {
	return nil
}

// denyFaultAuthz rejects every fault injection.
type denyFaultAuthz struct{}

func (denyFaultAuthz) AuthorizeFault(ctx context.Context, actor string, fault ChaosFaultType, target string) error {
	return errors.New("not permitted")
}

const testActor = "sre-operator"

func TestChaosEngine_RegionFailure(t *testing.T) {
	router := NewRegionalRouter()
	router.SetRegionStatus("us-east-1", true)

	engine := NewChaosEngine(router, allowAllFaultAuthz{})

	exp, err := engine.InjectFault(context.Background(), testActor, RegionFailure, "us-east-1", 5*time.Second)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	resilient, report, err := engine.VerifyResilience(exp.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !resilient {
		t.Errorf("expected system to be resilient")
	}
	if report == "" {
		t.Errorf("expected a report")
	}

	err = engine.HaltExperiment(exp.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !router.IsRegionActive("us-east-1") {
		t.Errorf("expected region to be active again after halt")
	}
}

func TestChaosEngine_AIProviderOutage(t *testing.T) {
	engine := NewChaosEngine(nil, allowAllFaultAuthz{})

	exp, err := engine.InjectFault(context.Background(), testActor, AIProviderOutage, "openai-primary", 2*time.Second)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	resilient, report, err := engine.VerifyResilience(exp.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !resilient {
		t.Errorf("expected resilience to be true")
	}
	if report == "" {
		t.Errorf("expected a report")
	}
}

func TestChaosEngine_MaliciousTenantAttack(t *testing.T) {
	engine := NewChaosEngine(nil, allowAllFaultAuthz{})

	exp, err := engine.InjectFault(context.Background(), testActor, MaliciousTenantAttack, "tenant-666", 1*time.Minute)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	resilient, report, err := engine.VerifyResilience(exp.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !resilient {
		t.Errorf("expected resilience to be true")
	}
	if report == "" {
		t.Errorf("expected a report")
	}
}

// TestChaosEngine_NilAuthorizerFailsClosed verifies that an engine without an
// authorizer denies all injection (destructive primitive, default-closed).
func TestChaosEngine_NilAuthorizerFailsClosed(t *testing.T) {
	engine := NewChaosEngine(NewRegionalRouter(), nil)

	exp, err := engine.InjectFault(context.Background(), testActor, RegionFailure, "us-east-1", time.Second)
	if err == nil {
		t.Fatal("expected fail-closed denial with nil authorizer")
	}
	if exp != nil {
		t.Errorf("expected nil experiment on denial, got %v", exp)
	}
}

// TestChaosEngine_AuthorizerDenies verifies a rejecting authorizer blocks injection
// and that no region status side effect leaks through.
func TestChaosEngine_AuthorizerDenies(t *testing.T) {
	router := NewRegionalRouter()
	router.SetRegionStatus("us-east-1", true)
	engine := NewChaosEngine(router, denyFaultAuthz{})

	exp, err := engine.InjectFault(context.Background(), testActor, RegionFailure, "us-east-1", time.Second)
	if err == nil {
		t.Fatal("expected denial from rejecting authorizer")
	}
	if exp != nil {
		t.Errorf("expected nil experiment on denial, got %v", exp)
	}
	if !router.IsRegionActive("us-east-1") {
		t.Errorf("denied injection must not take the region offline")
	}
}

// TestChaosEngine_EmptyActorDenied verifies injection requires a named actor.
func TestChaosEngine_EmptyActorDenied(t *testing.T) {
	engine := NewChaosEngine(NewRegionalRouter(), allowAllFaultAuthz{})

	if _, err := engine.InjectFault(context.Background(), "", RegionFailure, "us-east-1", time.Second); err == nil {
		t.Fatal("expected denial for empty actor")
	}
}
