//go:build !enterprise

// Bu dosya, VARSAYILAN (Lite) build'de derlenir. Enterprise katmanı derlenmediğinden
// Enable fail-closed davranır ve hiçbir ağır bağımlılık import edilmez (zero-dep korunur).
package enterprise

import (
	"errors"

	"kut.corp/suite/server/internal/eventbus"
)

// Edition, Lite build'de sürümü etiketler.
const Edition = "Lite"

// ErrNotCompiled, Enterprise özelliklerinin bu binary'de derlenmediğini bildirir.
var ErrNotCompiled = errors.New("enterprise: bu build'de derlenmedi (-tags enterprise ile derleyin)")

// Enable, Lite build'de no-op'tur ve ErrNotCompiled döner (imza enterprise ile birebir aynı).
func Enable(_ *eventbus.Bus) error { return ErrNotCompiled }

// Shutdown, Lite build'de no-op'tur (imza enterprise ile birebir aynı — stub-drift önlenir).
func Shutdown() error { return nil }
