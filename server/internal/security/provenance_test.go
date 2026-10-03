package security

import (
	"testing"
)

func TestProvenance(t *testing.T) {
	pv := NewProvenanceVerifier()

	artifacts := map[string][]byte{
		"binary.exe":  []byte("fake executable content"),
		"config.json": []byte(`{"key":"value"}`),
	}

	prov, err := pv.GenerateProvenance("https://github.com/kut/repo", "abcdef123456", "trusted-builder-1", artifacts)
	if err != nil {
		t.Fatalf("Failed to generate provenance: %v", err)
	}

	if prov.SLSAAttestation != "SLSA_BUILD_LEVEL_3" {
		t.Errorf("Expected SLSA_BUILD_LEVEL_3, got %s", prov.SLSAAttestation)
	}
	if len(prov.ArtifactHashes) != 2 {
		t.Errorf("Expected 2 hashes, got %d", len(prov.ArtifactHashes))
	}
	if prov.BuildID == "" {
		t.Errorf("Expected BuildID to be populated")
	}

	// Test valid artifact match
	valid, reason := pv.VerifyArtifact(prov, "binary.exe", []byte("fake executable content"))
	if !valid {
		t.Errorf("Expected valid artifact, got false: %s", reason)
	}

	// Test modified artifact rejection
	valid, reason = pv.VerifyArtifact(prov, "binary.exe", []byte("modified content"))
	if valid {
		t.Errorf("Expected modified artifact to fail verification")
	}
	if reason != "hash mismatch" {
		t.Errorf("Expected 'hash mismatch', got '%s'", reason)
	}

	// Test unknown artifact handling
	valid, reason = pv.VerifyArtifact(prov, "unknown.txt", []byte("stuff"))
	if valid {
		t.Errorf("Expected unknown artifact to fail verification")
	}
	if reason != "artifact not found in provenance" {
		t.Errorf("Expected 'artifact not found in provenance', got '%s'", reason)
	}

	// Test nil provenance handling
	valid, reason = pv.VerifyArtifact(nil, "binary.exe", []byte("fake executable content"))
	if valid {
		t.Errorf("Expected nil provenance to fail")
	}
	if reason != "nil provenance" {
		t.Errorf("Expected 'nil provenance', got '%s'", reason)
	}
}
