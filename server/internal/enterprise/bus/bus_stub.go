//go:build !enterprise

// Lite build yer-tutucusu: enterprise bus seam'i derlenmez. Paketin Lite'ta da geçerli
// olması için gereklidir; hiçbir dış bağımlılık import etmez. Lite'ta çağrılmaz.
package bus

import (
	"errors"

	"kut.corp/suite/server/internal/eventbus"
)

// Register, Lite build'de derlenmez (enterprise seam yok).
func Register(_ *eventbus.Bus) error { return errors.New("enterprise bus: derlenmedi") }
