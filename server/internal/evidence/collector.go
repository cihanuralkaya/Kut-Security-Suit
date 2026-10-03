package evidence

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ArtifactKind represents the type of collected evidence.
type ArtifactKind string

const (
	ArtifactProcessTree    ArtifactKind = "ProcessTree"
	ArtifactNetworkSockets ArtifactKind = "NetworkSockets"
	ArtifactMemoryMetadata ArtifactKind = "MemoryMetadata"
	ArtifactDiskArtifact   ArtifactKind = "DiskArtifact"
)

// LiveArtifact represents a collected forensics artifact.
type LiveArtifact struct {
	ID                 string
	TenantID           string
	DeviceID           string
	Kind               ArtifactKind
	RawContent         []byte
	SHA256Hash         string
	CollectedAt        time.Time
	CollectorSignature string
}

// EvidenceCollector handles collection and verification of digital forensics artifacts.
type EvidenceCollector struct{}

// NewEvidenceCollector creates a new EvidenceCollector instance.
func NewEvidenceCollector() *EvidenceCollector {
	return &EvidenceCollector{}
}

// CollectArtifact collects an artifact, generates an ID, and computes its SHA-256 hash.
// It ensures tenant isolation by validating tenantID and deviceID.
func (c *EvidenceCollector) CollectArtifact(tenantID string, deviceID string, kind ArtifactKind, content []byte) (*LiveArtifact, error) {
	if tenantID == "" {
		return nil, errors.New("tenantID cannot be empty")
	}
	if deviceID == "" {
		return nil, errors.New("deviceID cannot be empty")
	}
	if len(content) == 0 {
		return nil, errors.New("content cannot be empty")
	}

	hash := sha256.Sum256(content)
	hashStr := hex.EncodeToString(hash[:])

	// ID oluşturma (Generate ID)
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("failed to generate artifact ID: %w", err)
	}
	id := hex.EncodeToString(b)

	artifact := &LiveArtifact{
		ID:          id,
		TenantID:    tenantID,
		DeviceID:    deviceID,
		Kind:        kind,
		RawContent:  content,
		SHA256Hash:  hashStr,
		CollectedAt: time.Now().UTC(),
	}

	return artifact, nil
}

// VerifyArtifactIntegrity recomputes the SHA-256 hash of the RawContent and compares it.
// If the content is modified, this returns false.
func (c *EvidenceCollector) VerifyArtifactIntegrity(artifact *LiveArtifact) bool {
	if artifact == nil {
		return false
	}
	hash := sha256.Sum256(artifact.RawContent)
	expectedHash := hex.EncodeToString(hash[:])
	return expectedHash == artifact.SHA256Hash
}
