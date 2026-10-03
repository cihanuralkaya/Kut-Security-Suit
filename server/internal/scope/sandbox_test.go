package scope

import (
	"testing"
	"time"
)

func TestSandboxGuardrail_ValidateScript(t *testing.T) {
	guardrail := NewSandboxGuardrail()
	policy := DefaultSandboxPolicy()

	tests := []struct {
		name          string
		runtime       string
		script        []byte
		wantAllowed   bool
		wantViolation string
	}{
		{
			name:        "Benign script passes",
			runtime:     "bash",
			script:      []byte("echo 'Hello World'"),
			wantAllowed: true,
		},
		{
			name:          "Empty script fails",
			runtime:       "python",
			script:        []byte(""),
			wantAllowed:   false,
			wantViolation: "script content is empty",
		},
		{
			name:          "Disallowed runtime fails",
			runtime:       "node",
			script:        []byte("console.log('hi')"),
			wantAllowed:   false,
			wantViolation: "disallowed runtime: node",
		},
		{
			name:          "Destructive command rm -rf",
			runtime:       "bash",
			script:        []byte("echo 'cleaning'; rm -rf /"),
			wantAllowed:   false,
			wantViolation: "disallowed pattern found: rm -rf",
		},
		{
			name:          "Destructive command vssadmin",
			runtime:       "powershell",
			script:        []byte("vssadmin Delete Shadows /All /Quiet"),
			wantAllowed:   false,
			wantViolation: "disallowed pattern found: vssadmin delete shadows",
		},
		{
			name:          "Destructive command case insensitive",
			runtime:       "powershell",
			script:        []byte("INVOKE-MIMIKATZ -DumpCreds"),
			wantAllowed:   false,
			wantViolation: "disallowed pattern found: Invoke-Mimikatz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, violations := guardrail.ValidateScript(tt.runtime, tt.script, policy)
			if allowed != tt.wantAllowed {
				t.Errorf("ValidateScript() allowed = %v, want %v", allowed, tt.wantAllowed)
			}

			if !tt.wantAllowed && tt.wantViolation != "" {
				found := false
				for _, v := range violations {
					if v == tt.wantViolation {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("ValidateScript() violations = %v, want to contain %v", violations, tt.wantViolation)
				}
			}
		})
	}
}

func TestDefaultSandboxPolicy(t *testing.T) {
	policy := DefaultSandboxPolicy()
	if policy.MaxExecutionTime != 30*time.Second {
		t.Errorf("Expected MaxExecutionTime to be 30s, got %v", policy.MaxExecutionTime)
	}
	if len(policy.AllowedRuntimes) != 4 {
		t.Errorf("Expected 4 allowed runtimes, got %d", len(policy.AllowedRuntimes))
	}
}
