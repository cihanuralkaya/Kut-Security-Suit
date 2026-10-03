package aiprovider

import (
	"testing"
)

func TestDataClassifier_ClassifyText(t *testing.T) {
	classifier := NewDataClassifier()

	tests := []struct {
		name     string
		text     string
		expected Sensitivity
	}{
		{
			name:     "Credentials",
			text:     "Here is the database password=supersecret!",
			expected: Restricted,
		},
		{
			name:     "Private Key",
			text:     "-----BEGIN RSA PRIVATE KEY-----\nMIIE",
			expected: Restricted,
		},
		{
			name:     "AWS Secret Token",
			text:     "Use AKIAIOSFODNN7EXAMPLE for access",
			expected: Restricted,
		},
		{
			name:     "SSN",
			text:     "User SSN is 123-45-6789",
			expected: Restricted,
		},
		{
			name:     "TCKN",
			text:     "TCKN 12345678901 requested access",
			expected: Restricted,
		},
		{
			name:     "Internal IP",
			text:     "Connected to 10.0.0.1",
			expected: Restricted,
		},
		{
			name:     "Internal Hostname",
			text:     "Host is db01.internal",
			expected: Confidential,
		},
		{
			name:     "Email Address",
			text:     "Contact admin@example.com",
			expected: Confidential,
		},
		{
			name:     "Internal Metrics",
			text:     "CPU metrics are high",
			expected: Internal,
		},
		{
			name:     "Public CVE",
			text:     "CVE-2021-44228 allows RCE via JNDI",
			expected: Public,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifier.ClassifyText(tt.text)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestDataClassifier_ClassifyEvent(t *testing.T) {
	classifier := NewDataClassifier()

	tests := []struct {
		name     string
		category string
		severity string
		details  string
		expected Sensitivity
	}{
		{
			name:     "Critical Auth Failure",
			category: "auth",
			severity: "critical",
			details:  "User failed to login 10 times",
			expected: Restricted,
		},
		{
			name:     "Critical Auth with Internal IP",
			category: "auth",
			severity: "critical",
			details:  "Failed login from 10.1.2.3",
			expected: Restricted,
		},
		{
			name:     "Normal Auth Failure",
			category: "auth",
			severity: "low",
			details:  "User typed wrong password", 
			expected: Public, 
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifier.ClassifyEvent(tt.category, tt.severity, tt.details)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}
