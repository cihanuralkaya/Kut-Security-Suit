package security

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateKutSBOM(t *testing.T) {
	gen := NewSBOMGenerator()
	components := []SBOMComponent{
		{
			Name:           "test-lib",
			Version:        "1.0.0",
			Type:           ComponentTypeLibrary,
			License:        "MIT",
			PURL:           "pkg:golang/test-lib@1.0.0",
			SHA256Checksum: "dummyhash",
		},
	}

	doc, err := gen.GenerateKutSBOM("1.0.0", components)
	if err != nil {
		t.Fatalf("Failed to generate SBOM: %v", err)
	}

	if doc.DocumentID == "" {
		t.Error("Expected DocumentID, got empty string")
	}
	if !strings.HasPrefix(doc.DocumentID, "urn:uuid:") {
		t.Errorf("Expected DocumentID to be urn:uuid, got %s", doc.DocumentID)
	}
	if doc.Format != "CycloneDX-1.5" {
		t.Errorf("Expected format CycloneDX-1.5, got %s", doc.Format)
	}
	if len(doc.Components) != 1 {
		t.Errorf("Expected 1 component, got %d", len(doc.Components))
	}
	if doc.Components[0].Name != "test-lib" {
		t.Errorf("Expected component name 'test-lib', got %s", doc.Components[0].Name)
	}
}

func TestVerifyComponentChecksum(t *testing.T) {
	gen := NewSBOMGenerator()
	
	content := []byte("this is some test content")
	hash := sha256.Sum256(content)
	hexHash := hex.EncodeToString(hash[:])

	comp := SBOMComponent{
		Name:           "test-binary",
		SHA256Checksum: hexHash,
	}

	// Test successful verification
	if !gen.VerifyComponentChecksum(comp, content) {
		t.Error("Expected valid content to pass verification")
	}

	// Test tamper detection
	tamperedContent := []byte("this is some tampered content")
	if gen.VerifyComponentChecksum(comp, tamperedContent) {
		t.Error("Expected tampered content to fail verification")
	}
}

func TestExportJSON(t *testing.T) {
	gen := NewSBOMGenerator()
	components := []SBOMComponent{
		{
			Name:           "json-lib",
			Version:        "2.0",
			Type:           ComponentTypeLibrary,
		},
	}
	
	doc, _ := gen.GenerateKutSBOM("1.0.0", components)
	
	data, err := gen.ExportJSON(doc)
	if err != nil {
		t.Fatalf("Failed to export JSON: %v", err)
	}

	if len(data) == 0 {
		t.Error("Expected JSON data, got empty byte array")
	}
	
	jsonString := string(data)
	if !strings.Contains(jsonString, `"name": "json-lib"`) {
		t.Error("JSON output missing component name")
	}
	if !strings.Contains(jsonString, `"CycloneDX-1.5"`) {
		t.Error("JSON output missing format")
	}
}
