package aiprovider

import (
	"testing"
)

func TestModelRegistry_RegisterModel(t *testing.T) {
	registry := NewModelRegistry()

	m := ModelMetadata{
		ID:           "test-model",
		ProviderName: "TestProvider",
		Capabilities: []ModelCapability{CapabilityTriage},
		IsLocal:      false,
		Healthy:      true,
	}

	err := registry.RegisterModel(m)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	err = registry.RegisterModel(m)
	if err == nil {
		t.Fatalf("expected error for duplicate registration, got nil")
	}
}

func TestModelRegistry_SelectBestModel(t *testing.T) {
	registry := NewModelRegistry()

	_ = registry.RegisterModel(ModelMetadata{
		ID:           "cloud-fast",
		Capabilities: []ModelCapability{CapabilityTriage},
		IsLocal:      false,
		LatencyMs:    100,
		Healthy:      true,
	})

	_ = registry.RegisterModel(ModelMetadata{
		ID:           "cloud-slow",
		Capabilities: []ModelCapability{CapabilityTriage},
		IsLocal:      false,
		LatencyMs:    300,
		Healthy:      true,
	})

	_ = registry.RegisterModel(ModelMetadata{
		ID:           "local-fast",
		Capabilities: []ModelCapability{CapabilityTriage},
		IsLocal:      true,
		LatencyMs:    50,
		Healthy:      true,
	})

	_ = registry.RegisterModel(ModelMetadata{
		ID:           "local-fallback",
		Capabilities: []ModelCapability{CapabilityOfflineFallback},
		IsLocal:      true,
		LatencyMs:    10,
		Healthy:      true,
	})

	// Test selecting best overall (cloud-fast has 100ms, local-fast has 50ms)
	best, err := registry.SelectBestModel(CapabilityTriage, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if best.ID != "local-fast" {
		t.Errorf("expected local-fast, got %s", best.ID)
	}

	// Make local-fast unhealthy
	_ = registry.UpdateHealth("local-fast", false, 0)
	best, err = registry.SelectBestModel(CapabilityTriage, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if best.ID != "cloud-fast" {
		t.Errorf("expected cloud-fast, got %s", best.ID)
	}

	// Prefer local but only cloud is healthy for triage, should fallback to offline fallback
	best, err = registry.SelectBestModel(CapabilityTriage, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if best.ID != "local-fallback" {
		t.Errorf("expected local-fallback, got %s", best.ID)
	}

	// All models unhealthy, should error if no fallback is healthy
	_ = registry.UpdateHealth("cloud-fast", false, 0)
	_ = registry.UpdateHealth("cloud-slow", false, 0)
	_ = registry.UpdateHealth("local-fallback", false, 0)

	_, err = registry.SelectBestModel(CapabilityTriage, false)
	if err == nil {
		t.Fatalf("expected error when no models available")
	}
}

func TestLocalHeuristicClassifier(t *testing.T) {
	classifier := &LocalHeuristicClassifier{}

	tests := []struct {
		input    string
		expected string
	}{
		{"system('rm -rf /');", "HIGH_THREAT"},
		{"cat /etc/passwd", "MEDIUM_THREAT"},
		{"SELECT * FROM users WHERE 1=1", "MEDIUM_THREAT"},
		{"Hello world", "LOW_THREAT"},
	}

	for _, tc := range tests {
		result := classifier.Classify(tc.input)
		if result != tc.expected {
			t.Errorf("for input %q, expected %s, got %s", tc.input, tc.expected, result)
		}
	}
}
