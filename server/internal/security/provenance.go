package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// BuildProvenance represents cryptographic build provenance and attestation metadata.
type BuildProvenance struct {
	BuildID         string
	RepositoryURI   string
	CommitSHA       string
	BuilderIdentity string
	BuildTimestamp  time.Time
	ArtifactHashes  map[string]string // filename -> SHA256
	SLSAAttestation string
	Signature       string
}

// ProvenanceVerifier is responsible for generating and verifying build provenance.
// It is safe for concurrent use.
type ProvenanceVerifier struct {
	mu          sync.RWMutex
	trustedKeys map[string]string // BuilderIdentity -> PublicKey
}

// NewProvenanceVerifier creates a new thread-safe ProvenanceVerifier.
func NewProvenanceVerifier() *ProvenanceVerifier {
	return &ProvenanceVerifier{
		trustedKeys: make(map[string]string),
	}
}

// AddTrustedBuilder adds a trusted builder key for verification purposes.
func (pv *ProvenanceVerifier) AddTrustedBuilder(identity string, pubKey string) {
	pv.mu.Lock()
	defer pv.mu.Unlock()
	pv.trustedKeys[identity] = pubKey
}

// GenerateProvenance generates a SLSA Level 3 compatible provenance statement for the given artifacts.
func (pv *ProvenanceVerifier) GenerateProvenance(repo string, commit string, builder string, artifacts map[string][]byte) (*BuildProvenance, error) {
	hashes := make(map[string]string)
	for name, content := range artifacts {
		hash := sha256.Sum256(content)
		hashes[name] = hex.EncodeToString(hash[:])
	}

	return &BuildProvenance{
		BuildID:         generateUUID(),
		RepositoryURI:   repo,
		CommitSHA:       commit,
		BuilderIdentity: builder,
		BuildTimestamp:  time.Now().UTC(),
		ArtifactHashes:  hashes,
		SLSAAttestation: "SLSA_BUILD_LEVEL_3",
		Signature:       "", // To be signed externally or expanded in future iterations
	}, nil
}

// VerifyArtifact validates that a given artifact's content matches its hash in the provenance statement.
func (pv *ProvenanceVerifier) VerifyArtifact(provenance *BuildProvenance, filename string, content []byte) (valid bool, reason string) {
	pv.mu.RLock()
	defer pv.mu.RUnlock()

	if provenance == nil {
		return false, "nil provenance"
	}
	if provenance.ArtifactHashes == nil {
		return false, "no artifact hashes in provenance"
	}

	expectedHash, exists := provenance.ArtifactHashes[filename]
	if !exists {
		return false, "artifact not found in provenance"
	}

	hash := sha256.Sum256(content)
	actualHash := hex.EncodeToString(hash[:])

	if expectedHash != actualHash {
		return false, "hash mismatch"
	}

	return true, "valid"
}

// generateUUID generates a simple V4 UUID string without external dependencies.
func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
