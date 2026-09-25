//go:build !enterprise

// Lite (varsayılan) build: veri düzlemi ayrı binary'si YALNIZ Enterprise'da vardır.
package main

import (
	"log"
	"os"
)

func main() {
	log.SetFlags(0)
	log.Println("KUT veri düzlemi yalnız Enterprise build'de mevcuttur: `go build -tags enterprise ./server/cmd/ingest`")
	os.Exit(1)
}
