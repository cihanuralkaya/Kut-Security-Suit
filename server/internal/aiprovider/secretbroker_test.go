package aiprovider

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSecretBroker_RegisterAndExecute(t *testing.T) {
	broker := NewSecretBroker()
	ctx := context.Background()

	handle, err := broker.RegisterSecret("virustotal", "vt-super-secret-key-12345", "threatintel.read", time.Hour)
	if err != nil {
		t.Fatalf("unexpected error registering secret: %v", err)
	}

	if !strings.HasPrefix(handle.ID, "sec-virustotal-") {
		t.Errorf("expected handle ID prefix sec-virustotal-, got %s", handle.ID)
	}

	// Successful execution
	res, err := broker.ExecuteWithSecret(ctx, handle.ID, "threatintel.read", func(secret string) (any, error) {
		if secret != "vt-super-secret-key-12345" {
			t.Errorf("expected vt-super-secret-key-12345, got %s", secret)
		}
		return "api call succeeded", nil
	})
	if err != nil {
		t.Fatalf("unexpected error executing with secret: %v", err)
	}
	if res != "api call succeeded" {
		t.Errorf("expected 'api call succeeded', got %v", res)
	}

	// Scope mismatch should fail
	_, err = broker.ExecuteWithSecret(ctx, handle.ID, "admin.write", func(secret string) (any, error) {
		return nil, nil
	})
	if err == nil {
		t.Fatal("expected error on scope mismatch")
	}

	// Non-existent handle should fail
	_, err = broker.ExecuteWithSecret(ctx, "invalid-handle", "threatintel.read", func(secret string) (any, error) {
		return nil, nil
	})
	if err == nil {
		t.Fatal("expected error on non-existent handle")
	}
}

func TestSecretBroker_Expiration(t *testing.T) {
	broker := NewSecretBroker()
	ctx := context.Background()

	// Expired immediately
	handle, err := broker.RegisterSecret("temp-token", "raw-secret", "temp", -time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = broker.ExecuteWithSecret(ctx, handle.ID, "temp", func(secret string) (any, error) {
		return nil, nil
	})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error, got %v", err)
	}
}

func TestSecretBroker_ScrubText(t *testing.T) {
	broker := NewSecretBroker()
	_, _ = broker.RegisterSecret("aws-key", "AKIAIOSFODNN7EXAMPLE", "cloud", time.Hour)

	input := "The error occurred using key AKIAIOSFODNN7EXAMPLE while contacting S3."
	clean := broker.ScrubText(input)

	if strings.Contains(clean, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("expected raw key to be scrubbed, got: %s", clean)
	}
	if !strings.Contains(clean, "<SECRET:aws-key>") {
		t.Errorf("expected <SECRET:aws-key> placeholder, got: %s", clean)
	}
}
