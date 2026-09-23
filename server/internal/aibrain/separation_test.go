package aibrain

import (
	"os"
	"strings"
	"testing"
)

// aibrainForbiddenImports, AI danışma sınırının (aibrain) ASLA import ETMEMESİ gereken
// yürütme/yetki sınır paketleridir. Bu, "güvenlik sistemi AI'ı yönetir" ilkesinin YAPISAL
// güvencesidir: aibrain yalnız ÖNERİ/SİNYAL üretir (özet, triyaj, skor, açıklama) — hiçbir
// aksiyonu yürütemez/yetkilendiremez/karantinaya alamaz/silemez, çünkü DERLEME ZAMANINDA o
// paketlere erişimi yoktur. Yüksek-etkili her aksiyon yine §0 authz gateway zincirinden geçer.
var aibrainForbiddenImports = []string{
	"server/internal/seccontract",
	"server/internal/secgateway",
	"server/internal/privman",
	"server/internal/admin",
	"server/internal/adminapi",
	"server/internal/grpc",
	"server/internal/db",
	"server/internal/memstore",
}

// TestAibrainCannotReachEnforcement, aibrain kaynak dosyalarının hiçbirinin yürütme/yetki
// sınır paketlerini import etmediğini doğrular. İhlal → CI kırılır; AI düzleminin öneriden
// aksiyona geçmesi (authorize/quarantine/wipe/disable) derleyici düzeyinde engellenir.
func TestAibrainCannotReachEnforcement(t *testing.T) {
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
		for _, imp := range aibrainForbiddenImports {
			if strings.Contains(src, imp) {
				t.Errorf("AI-enforcement ihlali: %s, yasak sınır paketini import ediyor: %s", name, imp)
			}
		}
	}
}
