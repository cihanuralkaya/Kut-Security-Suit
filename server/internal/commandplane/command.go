package commandplane

import (
	"errors"
	"time"

	"kut.corp/suite/cmdenvelope"
)

// CommandType defines the available command types.
type CommandType string

const (
	TypeQuarantine         CommandType = cmdenvelope.TypeQuarantine
	TypeUnquarantine       CommandType = cmdenvelope.TypeUnquarantine
	TypeLock               CommandType = cmdenvelope.TypeLock
	TypeRestart            CommandType = cmdenvelope.TypeRestart
	TypeWipe               CommandType = cmdenvelope.TypeWipe
	TypeRunSignedScript    CommandType = cmdenvelope.TypeRunSignedScript
	TypeCollectFile        CommandType = cmdenvelope.TypeCollectFile
	TypeCollectDiagnostics CommandType = cmdenvelope.TypeCollectDiagnostics
	TypeUninstall          CommandType = cmdenvelope.TypeUninstall
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

	// Tip, paylaşılan komut tablosunda (cmdenvelope) kayıtlı olmalı; bilinmeyen tip
	// fail-closed reddedilir.
	if _, ok := Spec(r.Type); !ok {
		return errors.New("invalid command type")
	}
	return nil
}

// Spec, komut tipinin paylaşılan tablodaki tanımını döner (sınıf, rol, scope eşlemesi,
// korumalılık). Kayıtsız tip için ok=false — çağıran REDDETMELİDİR.
func Spec(t CommandType) (cmdenvelope.Spec, bool) {
	return cmdenvelope.Lookup(string(t))
}
