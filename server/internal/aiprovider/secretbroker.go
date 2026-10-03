package aiprovider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// SecretHandle represents an opaque reference to a secret stored in the Secret Broker.
// AI agents and LLMs ONLY see this handle, never the underlying raw secret value.
type SecretHandle struct {
	ID        string    `json:"handle_id"`
	Name      string    `json:"name"`
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
}

type secretEntry struct {
	handle SecretHandle
	value  string
}

// SecretBroker isolates raw credentials from AI agents and autonomous tool execution.
// Agents execute operations via opaque handles; secrets are injected at runtime
// and never leaked into prompt contexts.
type SecretBroker struct {
	mu      sync.RWMutex
	secrets map[string]secretEntry // handleID -> entry
}

// NewSecretBroker creates a new SecretBroker.
func NewSecretBroker() *SecretBroker {
	return &SecretBroker{
		secrets: make(map[string]secretEntry),
	}
}

// RegisterSecret securely registers a credential and returns an opaque handle.
func (b *SecretBroker) RegisterSecret(name, value, scope string, ttl time.Duration) (SecretHandle, error) {
	if strings.TrimSpace(name) == "" {
		return SecretHandle{}, errors.New("secret name cannot be empty")
	}
	if strings.TrimSpace(value) == "" {
		return SecretHandle{}, errors.New("secret value cannot be empty")
	}

	rb := make([]byte, 8)
	_, _ = rand.Read(rb)
	handleID := fmt.Sprintf("sec-%s-%s", name, hex.EncodeToString(rb))

	var exp time.Time
	if ttl != 0 {
		exp = time.Now().Add(ttl)
	}

	handle := SecretHandle{
		ID:        handleID,
		Name:      name,
		Scope:     scope,
		ExpiresAt: exp,
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.secrets[handleID] = secretEntry{
		handle: handle,
		value:  value,
	}

	return handle, nil
}

// ExecuteWithSecret allows a controlled operation to access the secret inside a closure
// without exposing the secret to the outer agent or prompting context.
func (b *SecretBroker) ExecuteWithSecret(ctx context.Context, handleID, requiredScope string, fn func(secret string) (any, error)) (any, error) {
	b.mu.RLock()
	entry, exists := b.secrets[handleID]
	b.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("secret handle not found: %s", handleID)
	}

	if !entry.handle.ExpiresAt.IsZero() && time.Now().After(entry.handle.ExpiresAt) {
		return nil, fmt.Errorf("secret handle has expired: %s", handleID)
	}

	if requiredScope != "" && entry.handle.Scope != requiredScope {
		return nil, fmt.Errorf("scope mismatch: required %q, handle has %q", requiredScope, entry.handle.Scope)
	}

	// Secret runtime injection
	return fn(entry.value)
}

// ScrubText removes any known raw secret values from text outputs before returning to agents.
func (b *SecretBroker) ScrubText(text string) string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, entry := range b.secrets {
		if entry.value != "" {
			text = strings.ReplaceAll(text, entry.value, fmt.Sprintf("<SECRET:%s>", entry.handle.Name))
		}
	}
	return text
}
