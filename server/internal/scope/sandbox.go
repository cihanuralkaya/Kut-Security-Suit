package scope

import (
	"bytes"
	"strings"
	"time"
)

// SandboxPolicy defines the constraints for script execution.
type SandboxPolicy struct {
	MaxExecutionTime   time.Duration
	MaxMemoryBytes     int64
	DisallowedPatterns []string
	AllowedRuntimes    []string
}

// DefaultSandboxPolicy returns a SandboxPolicy with secure defaults.
func DefaultSandboxPolicy() SandboxPolicy {
	return SandboxPolicy{
		MaxExecutionTime: 30 * time.Second,
		MaxMemoryBytes:   50 * 1024 * 1024, // 50MB default limit
		DisallowedPatterns: []string{
			"rm -rf",
			"Format-Volume",
			"Invoke-Mimikatz",
			"vssadmin delete shadows",
			"Set-ExecutionPolicy Bypass",
		},
		AllowedRuntimes: []string{"powershell", "bash", "python", "sh"},
	}
}

// SandboxGuardrail provides validation for script execution.
type SandboxGuardrail struct{}

// NewSandboxGuardrail creates a new SandboxGuardrail.
func NewSandboxGuardrail() *SandboxGuardrail {
	return &SandboxGuardrail{}
}

// ValidateScript checks a script against the provided policy.
// It fails closed: if it violates constraints or if the runtime is not allowed.
func (g *SandboxGuardrail) ValidateScript(runtime string, scriptContent []byte, policy SandboxPolicy) (allowed bool, violations []string) {
	allowed = true

	// Check runtime
	runtimeAllowed := false
	for _, r := range policy.AllowedRuntimes {
		if strings.EqualFold(r, runtime) {
			runtimeAllowed = true
			break
		}
	}
	if !runtimeAllowed {
		allowed = false
		violations = append(violations, "disallowed runtime: "+runtime)
	}

	if len(scriptContent) == 0 {
		allowed = false
		violations = append(violations, "script content is empty")
	}

	// Check forbidden patterns
	upperScript := bytes.ToUpper(scriptContent)
	for _, pattern := range policy.DisallowedPatterns {
		upperPattern := []byte(strings.ToUpper(pattern))
		if bytes.Contains(upperScript, upperPattern) {
			allowed = false
			violations = append(violations, "disallowed pattern found: "+pattern)
		}
	}

	return allowed, violations
}
