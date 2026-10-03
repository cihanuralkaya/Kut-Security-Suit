package commandplane

import (
	"context"
	"errors"
	"sync"
)

// CommandStore defines the storage interface for commands.
type CommandStore interface {
	EnqueueCommand(ctx context.Context, deviceID string, cmdType CommandType, issuedBy string, params map[string]any) (string, error)
	GetPendingCommands(ctx context.Context, deviceID string) ([]CommandRecord, error)
	AckCommand(ctx context.Context, commandID string, status CommandState, detail string) error
}

// AuthorizationDecision represents a basic decision.
type AuthorizationDecision struct {
	Allowed bool
	Reason  string
}

// ActionRequest represents a request for authorization.
type ActionRequest struct {
	Subject string // IssuedBy
	Action  string // CommandType
	Object  string // DeviceID
}

// Authorizer defines the authorization interface.
type Authorizer interface {
	Authorize(ctx context.Context, req ActionRequest) (AuthorizationDecision, error)
}

// Plane encapsulates the command plane logic.
type Plane struct {
	store   CommandStore
	authz   Authorizer
	mu      sync.RWMutex
	running bool
}

// NewPlane creates a new CommandPlane instance.
func NewPlane(store CommandStore, authz Authorizer) *Plane {
	return &Plane{
		store: store,
		authz: authz,
	}
}

// Start starts the command plane.
func (p *Plane) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return errors.New("command plane already running")
	}
	p.running = true
	return nil
}

// Stop stops the command plane.
func (p *Plane) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running {
		return errors.New("command plane not running")
	}
	p.running = false
	return nil
}

// Dispatch validates the request, checks authorization, and enqueues the command.
func (p *Plane) Dispatch(ctx context.Context, req CommandRequest) (string, error) {
	if err := req.Validate(); err != nil {
		return "", err
	}

	authReq := ActionRequest{
		Subject: req.IssuedBy,
		Action:  string(req.Type),
		Object:  req.DeviceID,
	}

	// Yetki kontrolü (fail-closed)
	decision, err := p.authz.Authorize(ctx, authReq)
	if err != nil {
		return "", err
	}
	if !decision.Allowed {
		return "", errors.New("authorization denied: " + decision.Reason)
	}

	// Yetkilendirme basarili, komutu kuyruga ekle.
	cmdID, err := p.store.EnqueueCommand(ctx, req.DeviceID, req.Type, req.IssuedBy, req.Params)
	if err != nil {
		return "", err
	}

	return cmdID, nil
}

// HandleCommandResult updates the command status based on the result.
func (p *Plane) HandleCommandResult(ctx context.Context, deviceID, commandID string, success bool, detail string) error {
	status := StateFailed
	if success {
		status = StateSucceeded
	}
	// Durum güncellemesi yap.
	return p.store.AckCommand(ctx, commandID, status, detail)
}
