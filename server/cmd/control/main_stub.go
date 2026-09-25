//go:build !enterprise

// Lite (varsayılan) build: kontrol düzlemi ayrı binary'si YALNIZ Enterprise'da vardır.
// Bu stub, Lite'ta geçerli bir `main` sağlar ve `-tags enterprise` gerektiğini bildirir.
package main

import (
	"log"
	"os"
)

func main() {
	log.SetFlags(0)
	log.Println("KUT kontrol düzlemi yalnız Enterprise build'de mevcuttur: `go build -tags enterprise ./server/cmd/control`")
	os.Exit(1)
}
