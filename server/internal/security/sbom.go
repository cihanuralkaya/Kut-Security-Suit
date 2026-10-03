package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type ComponentType string

const (
	ComponentTypeLibrary   ComponentType = "library"
	ComponentTypeFramework ComponentType = "framework"
	ComponentTypeBinary    ComponentType = "binary"
	ComponentTypeModel     ComponentType = "model"
	ComponentTypeTool      ComponentType = "tool"
)

type SBOMComponent struct {
	Name           string        `json:"name"`
	Version        string        `json:"version"`
	Type           ComponentType `json:"type"`
	License        string        `json:"license"`
	PURL           string        `json:"purl"`
	SHA256Checksum string        `json:"sha256_checksum"`
}

type SBOMDocument struct {
	DocumentID string          `json:"document_id"`
	Format     string          `json:"format"`
	Timestamp  time.Time       `json:"timestamp"`
	Components []SBOMComponent `json:"components"`
	Signature  string          `json:"signature"`
}

type SBOMGenerator struct{}

func NewSBOMGenerator() *SBOMGenerator {
	return &SBOMGenerator{}
}

func (g *SBOMGenerator) GenerateKutSBOM(version string, components []SBOMComponent) (*SBOMDocument, error) {
	// Generate a unique Document ID
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	docID := fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])

	doc := &SBOMDocument{
		DocumentID: docID,
		Format:     "CycloneDX-1.5",
		Timestamp:  time.Now().UTC(),
		Components: components,
	}
	return doc, nil
}

func (g *SBOMGenerator) VerifyComponentChecksum(comp SBOMComponent, actualContent []byte) bool {
	hash := sha256.Sum256(actualContent)
	calculatedChecksum := hex.EncodeToString(hash[:])
	return calculatedChecksum == comp.SHA256Checksum
}

func (g *SBOMGenerator) ExportJSON(doc *SBOMDocument) ([]byte, error) {
	return json.MarshalIndent(doc, "", "  ")
}
