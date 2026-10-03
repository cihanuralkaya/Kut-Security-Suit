package controlplane

import "time"

// EnrollRequest represents an agent registration payload.
type EnrollRequest struct {
	EnrollmentToken string
	CSRPEM          []byte
	Hostname        string
	MACAddress      string
	OSInfo          string
}

// EnrollResponse represents the enrollment confirmation.
type EnrollResponse struct {
	DeviceID      string
	ClientCertPEM []byte
	CAChainPEM    []byte
	NotAfter      time.Time
}

// PolicyRule defines an individual policy rule.
type PolicyRule struct {
	RuleID      string
	Type        string
	TargetValue string
}

// PolicyBundle represents a versioned set of policies for an endpoint.
type PolicyBundle struct {
	PolicyVersion string
	Rules         []PolicyRule
	IssuedAt      time.Time
}

// AdminUser represents an authenticated administrator identity.
type AdminUser struct {
	ID       string
	Email    string
	Role     string
	TenantID string
}
