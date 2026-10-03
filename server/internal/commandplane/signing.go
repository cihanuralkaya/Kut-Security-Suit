package commandplane

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// SignedCommandEnvelope wraps an authorized command with a cryptographic signature,
// ensuring non-repudiation, integrity, and anti-replay (SEC-002 & SEC-005).
type SignedCommandEnvelope struct {
	CommandID string         `json:"command_id"`
	DeviceID  string         `json:"device_id"`
	Type      CommandType    `json:"type"`
	IssuedBy  string         `json:"issued_by"`
	Params    map[string]any `json:"params,omitempty"`
	Nonce     string         `json:"nonce"`
	IssuedAt  time.Time      `json:"issued_at"`
	ExpiresAt time.Time      `json:"expires_at"`
	Signature []byte         `json:"signature"` // Ed25519 signature
}

// CanonicalSigningBytes produces deterministic canonical bytes for signing or verification.
// Resolves SEC-005: avoids non-deterministic JSON key serialization issues by computing
// a sorted SHA-256 hash of parameters and binding all fields with explicit unit separators.
func CanonicalSigningBytes(cmdID, deviceID string, cmdType CommandType, issuedBy string, params map[string]any, nonce string, issuedAt, expiresAt time.Time) []byte {
	var b bytes.Buffer
	sep := byte(0x1f)

	b.WriteString(cmdID)
	b.WriteByte(sep)
	b.WriteString(deviceID)
	b.WriteByte(sep)
	b.WriteString(string(cmdType))
	b.WriteByte(sep)
	b.WriteString(issuedBy)
	b.WriteByte(sep)

	// Canonical parameters hash
	paramsHash := hashParams(params)
	b.Write(paramsHash)
	b.WriteByte(sep)

	b.WriteString(nonce)
	b.WriteByte(sep)
	b.WriteString(fmt.Sprintf("%d", issuedAt.UnixNano()))
	b.WriteByte(sep)
	b.WriteString(fmt.Sprintf("%d", expiresAt.UnixNano()))

	return b.Bytes()
}

func hashParams(params map[string]any) []byte {
	if len(params) == 0 {
		return []byte("empty")
	}

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte("="))
		valBytes, _ := json.Marshal(params[k])
		h.Write(valBytes)
		h.Write([]byte(";"))
	}
	return h.Sum(nil)
}

// CommandSigner signs command envelopes using an Ed25519 private key.
type CommandSigner struct {
	privKey ed25519.PrivateKey
	ttl     time.Duration
}

// NewCommandSigner creates a new CommandSigner.
func NewCommandSigner(privKey ed25519.PrivateKey, ttl time.Duration) *CommandSigner {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &CommandSigner{
		privKey: privKey,
		ttl:     ttl,
	}
}

// Sign crafts and signs an envelope for the given command request.
func (s *CommandSigner) Sign(cmdID string, req CommandRequest, now time.Time) (SignedCommandEnvelope, error) {
	if len(s.privKey) != ed25519.PrivateKeySize {
		return SignedCommandEnvelope{}, errors.New("invalid private key size")
	}

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return SignedCommandEnvelope{}, fmt.Errorf("failed to generate nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)

	issuedAt := now.UTC()
	expiresAt := issuedAt.Add(s.ttl)

	signBytes := CanonicalSigningBytes(cmdID, req.DeviceID, req.Type, req.IssuedBy, req.Params, nonce, issuedAt, expiresAt)
	sig := ed25519.Sign(s.privKey, signBytes)

	return SignedCommandEnvelope{
		CommandID: cmdID,
		DeviceID:  req.DeviceID,
		Type:      req.Type,
		IssuedBy:  req.IssuedBy,
		Params:    req.Params,
		Nonce:     nonce,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		Signature: sig,
	}, nil
}

// CommandVerifier verifies signed command envelopes using an Ed25519 public key.
type CommandVerifier struct {
	pubKey ed25519.PublicKey
}

// NewCommandVerifier creates a new CommandVerifier.
func NewCommandVerifier(pubKey ed25519.PublicKey) *CommandVerifier {
	return &CommandVerifier{pubKey: pubKey}
}

// Verify validates that the envelope signature is authentic, targeting the expected device,
// and has not expired.
func (v *CommandVerifier) Verify(env SignedCommandEnvelope, expectedDeviceID string, now time.Time) error {
	if len(v.pubKey) != ed25519.PublicKeySize {
		return errors.New("invalid public key size")
	}

	if expectedDeviceID != "" && env.DeviceID != expectedDeviceID {
		return fmt.Errorf("device ID mismatch: expected %s, got %s", expectedDeviceID, env.DeviceID)
	}

	if now.After(env.ExpiresAt) {
		return fmt.Errorf("command envelope expired at %s", env.ExpiresAt.Format(time.RFC3339))
	}

	if env.Nonce == "" {
		return errors.New("missing cryptographic nonce")
	}

	signBytes := CanonicalSigningBytes(env.CommandID, env.DeviceID, env.Type, env.IssuedBy, env.Params, env.Nonce, env.IssuedAt, env.ExpiresAt)
	if !ed25519.Verify(v.pubKey, signBytes, env.Signature) {
		return errors.New("cryptographic signature verification failed")
	}

	return nil
}
