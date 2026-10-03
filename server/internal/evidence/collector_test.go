package evidence

import (
	"testing"
)

func TestCollectArtifact_Success(t *testing.T) {
	collector := NewEvidenceCollector()
	content := []byte("suspicious process activity")

	artifact, err := collector.CollectArtifact("tenant-1", "device-a", ArtifactProcessTree, content)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if artifact.TenantID != "tenant-1" {
		t.Errorf("expected tenant-1, got %s", artifact.TenantID)
	}

	if artifact.DeviceID != "device-a" {
		t.Errorf("expected device-a, got %s", artifact.DeviceID)
	}

	if len(artifact.ID) == 0 {
		t.Error("expected non-empty artifact ID")
	}

	if artifact.SHA256Hash == "" {
		t.Error("expected non-empty hash")
	}

	if artifact.Kind != ArtifactProcessTree {
		t.Errorf("expected %s, got %s", ArtifactProcessTree, artifact.Kind)
	}

	if !collector.VerifyArtifactIntegrity(artifact) {
		t.Error("expected integrity check to pass")
	}
}

func TestCollectArtifact_ValidationFailures(t *testing.T) {
	collector := NewEvidenceCollector()

	_, err := collector.CollectArtifact("", "device-a", ArtifactNetworkSockets, []byte("data"))
	if err == nil {
		t.Error("expected error for empty tenantID")
	}

	_, err = collector.CollectArtifact("tenant-1", "", ArtifactNetworkSockets, []byte("data"))
	if err == nil {
		t.Error("expected error for empty deviceID")
	}

	_, err = collector.CollectArtifact("tenant-1", "device-a", ArtifactNetworkSockets, nil)
	if err == nil {
		t.Error("expected error for empty content")
	}
}

func TestVerifyArtifactIntegrity_TamperDetection(t *testing.T) {
	collector := NewEvidenceCollector()
	content := []byte("original memory dump")

	artifact, err := collector.CollectArtifact("tenant-1", "device-a", ArtifactMemoryMetadata, content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Doğrulama başarılı olmalı (Validation should pass)
	if !collector.VerifyArtifactIntegrity(artifact) {
		t.Error("expected integrity check to pass initially")
	}

	// İçeriği değiştirerek bütünlüğü bozalım (Tamper with the data)
	artifact.RawContent = []byte("tampered memory dump")

	// Doğrulama başarısız olmalı (Validation should fail)
	if collector.VerifyArtifactIntegrity(artifact) {
		t.Error("expected integrity check to fail after tampering")
	}
}

func TestVerifyArtifactIntegrity_NilArtifact(t *testing.T) {
	collector := NewEvidenceCollector()
	if collector.VerifyArtifactIntegrity(nil) {
		t.Error("expected false for nil artifact")
	}
}
