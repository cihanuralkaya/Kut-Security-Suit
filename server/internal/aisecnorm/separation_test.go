package aisecnorm

import (
	"os"
	"strings"
	"testing"
)

// normForbiddenImports, kanonik-olay köprüsünün (aisecnorm) ASLA import ETMEMESİ gereken
// yürütme/yetki sınır paketleridir. Köprü, gözlem düzleminin (aisec) bulgularını yalnız
// DATA'ya (model.Event) çevirir; enforcement üretmez (INV-AG-010). Yapısal güvence: köprü,
// derleme zamanında yürütme sınırına erişemez.
var normForbiddenImports = []string{
	"server/internal/seccontract",
	"server/internal/secgateway",
	"server/internal/privman",
	"server/internal/admin",
	"server/internal/adminapi",
	"server/internal/grpc",
	"server/internal/db",
	"server/internal/memstore",
}

// TestNormStaysObservationOnly, aisecnorm kaynak dosyalarının hiçbirinin yürütme/yetki sınır
// paketlerini import etmediğini doğrular. İhlal → CI kırılır; gözlem→kanonik-olay köprüsünün
// aksiyon yürütmeye sızması engellenir.
func TestNormStaysObservationOnly(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("paket dizini okunamadı: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("%s okunamadı: %v", name, err)
		}
		src := string(data)
		for _, imp := range normForbiddenImports {
			if strings.Contains(src, imp) {
				t.Errorf("gözlem-düzlemi ihlali: %s, yasak sınır paketini import ediyor: %s", name, imp)
			}
		}
	}
}
