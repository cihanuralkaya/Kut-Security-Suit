package coordinator

import (
	"testing"
	"time"
)

func TestChaosEngine_RegionFailure(t *testing.T) {
	router := NewRegionalRouter()
	router.SetRegionStatus("us-east-1", true)

	engine := NewChaosEngine(router)

	exp, err := engine.InjectFault(RegionFailure, "us-east-1", 5*time.Second)
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
	engine := NewChaosEngine(nil)

	exp, err := engine.InjectFault(AIProviderOutage, "openai-primary", 2*time.Second)
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
	engine := NewChaosEngine(nil)

	exp, err := engine.InjectFault(MaliciousTenantAttack, "tenant-666", 1*time.Minute)
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
