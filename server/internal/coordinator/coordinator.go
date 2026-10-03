package coordinator

import (
	"context"
	"errors"
	"sync"

	"kut.corp/suite/server/internal/commandplane"
	"kut.corp/suite/server/internal/controlplane"
	"kut.corp/suite/server/internal/telemetryplane"
)

// FabricCoordinator orchestrates the lifecycle and boundary interactions
// among KUT Security Fabric operational planes.
type FabricCoordinator struct {
	Control   *controlplane.Plane
	Telemetry *telemetryplane.Plane
	Command   *commandplane.Plane

	mu      sync.RWMutex
	running bool
}

// New creates a new FabricCoordinator instance.
func New(control *controlplane.Plane, telemetry *telemetryplane.Plane, command *commandplane.Plane) *FabricCoordinator {
	return &FabricCoordinator{
		Control:   control,
		Telemetry: telemetry,
		Command:   command,
	}
}

// Start boots all planes in dependency order:
// 1. Control Plane (auth, PKI, policies)
// 2. Command Plane (tasking and dispatching)
// 3. Telemetry Plane (data ingestion and alerting)
func (c *FabricCoordinator) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return errors.New("fabric coordinator already running")
	}

	if c.Control != nil {
		if err := c.Control.Start(ctx); err != nil {
			return err
		}
	}

	if c.Command != nil {
		if err := c.Command.Start(ctx); err != nil {
			_ = c.stopControl()
			return err
		}
	}

	if c.Telemetry != nil {
		if err := c.Telemetry.Start(ctx); err != nil {
			_ = c.stopCommand()
			_ = c.stopControl()
			return err
		}
	}

	c.running = true
	return nil
}

// Stop shuts down all planes in reverse dependency order:
// 1. Telemetry Plane (halt new ingress first)
// 2. Command Plane (finish or drain in-flight commands)
// 3. Control Plane (close administrative channels)
func (c *FabricCoordinator) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return errors.New("fabric coordinator not running")
	}

	var errs []error

	if c.Telemetry != nil {
		if err := c.Telemetry.Stop(); err != nil {
			errs = append(errs, err)
		}
	}

	if c.Command != nil {
		if err := c.Command.Stop(); err != nil {
			errs = append(errs, err)
		}
	}

	if c.Control != nil {
		if err := c.Control.Stop(); err != nil {
			errs = append(errs, err)
		}
	}

	c.running = false
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (c *FabricCoordinator) stopCommand() error {
	if c.Command != nil {
		return c.Command.Stop()
	}
	return nil
}

func (c *FabricCoordinator) stopControl() error {
	if c.Control != nil {
		return c.Control.Stop()
	}
	return nil
}

// IsRunning reports whether the fabric is active.
func (c *FabricCoordinator) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}
