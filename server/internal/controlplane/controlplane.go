package controlplane

import (
	"context"
	"errors"
	"sync"
)

// EnrollmentHandler manages the certificate lifecycle and initial device trust.
type EnrollmentHandler interface {
	Enroll(ctx context.Context, req EnrollRequest) (EnrollResponse, error)
}

// PolicyProvider manages the distribution of endpoint policies.
type PolicyProvider interface {
	GetPolicy(ctx context.Context, tenantID, deviceID string) (PolicyBundle, error)
}

// AdminStore handles administrative user authentication and RBAC.
type AdminStore interface {
	AuthenticateAdmin(ctx context.Context, email, password string) (AdminUser, error)
}

// Plane encapsulates the Control Plane coordination logic.
type Plane struct {
	enroll   EnrollmentHandler
	policies PolicyProvider
	admins   AdminStore

	mu      sync.RWMutex
	running bool
}

// New creates a new Control Plane instance.
func New(enroll EnrollmentHandler, policies PolicyProvider, admins AdminStore) *Plane {
	return &Plane{
		enroll:   enroll,
		policies: policies,
		admins:   admins,
	}
}

// Start boots the Control Plane lifecycle.
func (p *Plane) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return errors.New("control plane already running")
	}
	p.running = true
	return nil
}

// Stop shuts down the Control Plane lifecycle.
func (p *Plane) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running {
		return errors.New("control plane not running")
	}
	p.running = false
	return nil
}

// EnrollDevice delegates agent enrollment to the enrollment handler.
func (p *Plane) EnrollDevice(ctx context.Context, req EnrollRequest) (EnrollResponse, error) {
	p.mu.RLock()
	running := p.running
	p.mu.RUnlock()
	if !running {
		return EnrollResponse{}, errors.New("control plane is not running")
	}
	if p.enroll == nil {
		return EnrollResponse{}, errors.New("enrollment handler not configured")
	}
	return p.enroll.Enroll(ctx, req)
}

// FetchPolicyForDevice retrieves the effective policy bundle for an endpoint.
func (p *Plane) FetchPolicyForDevice(ctx context.Context, tenantID, deviceID string) (PolicyBundle, error) {
	p.mu.RLock()
	running := p.running
	p.mu.RUnlock()
	if !running {
		return PolicyBundle{}, errors.New("control plane is not running")
	}
	if p.policies == nil {
		return PolicyBundle{}, errors.New("policy provider not configured")
	}
	return p.policies.GetPolicy(ctx, tenantID, deviceID)
}

// Authenticate verifies admin credentials.
func (p *Plane) Authenticate(ctx context.Context, email, password string) (AdminUser, error) {
	p.mu.RLock()
	running := p.running
	p.mu.RUnlock()
	if !running {
		return AdminUser{}, errors.New("control plane is not running")
	}
	if p.admins == nil {
		return AdminUser{}, errors.New("admin store not configured")
	}
	return p.admins.AuthenticateAdmin(ctx, email, password)
}
