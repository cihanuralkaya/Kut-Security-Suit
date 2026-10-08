package commandplane

import (
	"errors"
	"time"
)

// CommandType defines the available command types.
type CommandType string

const (
	TypeQuarantine      CommandType = "QUARANTINE"
	TypeUnquarantine    CommandType = "UNQUARANTINE"
	TypeLock            CommandType = "LOCK"
	TypeRestart         CommandType = "RESTART"
	TypeWipe            CommandType = "WIPE"
	TypeRunSignedScript CommandType = "RUN_SIGNED_SCRIPT"
	TypeCollectFile     CommandType = "COLLECT_FILE"
)

// CommandState represents the current state of a command.
type CommandState string

const (
	StatePending   CommandState = "Pending"
	StateDelivered CommandState = "Delivered"
	StateSucceeded CommandState = "Succeeded"
	StateFailed    CommandState = "Failed"
)

// CommandRequest represents a request to dispatch a command.
type CommandRequest struct {
	DeviceID string
	Type     CommandType
	IssuedBy string
	Params   map[string]any
}

// CommandRecord represents a command stored in the system.
type CommandRecord struct {
	ID        string
	DeviceID  string
	Type      CommandType
	IssuedBy  string
	Params    map[string]any
	State     CommandState
	Detail    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Validate checks if the command request is valid.
func (r *CommandRequest) Validate() error {
	if r.DeviceID == "" {
		return errors.New("missing device ID")
	}
	if r.Type == "" {
		return errors.New("missing command type")
	}
	if r.IssuedBy == "" {
		return errors.New("missing issued by")
	}

	// WIPE komutu vb. komutlarin dogrulanmasi.
	switch r.Type {
	case TypeQuarantine, TypeUnquarantine, TypeLock, TypeRestart, TypeWipe, TypeRunSignedScript, TypeCollectFile:
		return nil
	default:
		return errors.New("invalid command type")
	}
}
