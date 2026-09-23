package aisec

import (
	"os"
	"strings"
	"testing"
)

// forbiddenImports, aisec'in (Agentic Threat Defense düzlemi) ASLA import ETMEMESİ
// gereken execution/authorization sınır paketleridir. Bu, INV-AG-010/011'in YAPISAL
// güvencesidir: AG düzlemi §1-13 execution freeze'ine dokunamaz/onu bypass edemez, çünkü
// derleme zamanında o paketlere erişimi yoktur (containment yalnız §0 zinciriyle uygulanır).
var forbiddenImports = []string{
	"server/internal/seccontract",
	"server/internal/secgateway",
	"server/internal/privman",
	"server/internal/admin",
	"server/internal/adminapi",
	"server/internal/grpc",
	"server/internal/db",
	"server/internal/memstore",
}

// TestAisecStaysSeparateFromExecutionBoundary, aisec kaynak dosyalarının hiçbirinin
// execution/authorization sınır paketlerini import etmediğini doğrular (INV-AG-010/011).
// İhlal → CI kırılır; AG düzleminin yürütme sınırına sızması engellenir.
func TestAisecStaysSeparateFromExecutionBoundary(t *testing.T) {
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
		for _, imp := range forbiddenImports {
			if strings.Contains(src, imp) {
				t.Errorf("INV-AG-010/011 ihlali: %s, yasak sınır paketini import ediyor: %s", name, imp)
			}
		}
	}
}
