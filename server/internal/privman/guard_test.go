package privman_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rawMutationMethods, authorization sınırını atlayarak çağrılması YASAK olan raw Store
// mutasyon metotlarıdır (audit §1/§4 G-02). Yeni eklenen mutasyonlar buraya eklenmelidir.
var rawMutationMethods = []string{
	"EnqueueCommand", "EnqueueCommandParams", "SetDeviceStatus", "SetDeviceTags",
	"AssignPolicy", "EraseDeviceData", "RevokeDeviceCerts", "SavePendingWipe",
	"DeletePendingWipe", "RevokeEnrollmentToken", "SetEventAck",
}

// allowedBoundaryDirs, raw mutasyonları çağırmasına İZİN VERİLEN mevcut sınır
// paketleridir (repo-göreli, "/" ayraçlı). Migration ilerledikçe (PR-03+) bu küme
// DARALIR: bir yol GuardedExecutor/privman sınırından geçince buradan çıkarılır.
var allowedBoundaryDirs = []string{
	"server/internal/admin",       // Store arayüzü + admin.Service (mevcut sınır)
	"server/internal/adminapi",    // HTTP handler'lar (admin.Service'e delege)
	"server/internal/response",    // AutoQuarantiner (PR-03'te sınıra taşınacak)
	"server/internal/memstore",    // Store impl (bellek)
	"server/internal/db",          // Store impl (DB)
	"server/internal/seccontract", // frozen sözleşme tipleri
	"server/internal/privman",     // bu paket
}

// repoRoot, go.mod'a kadar yukarı yürüyerek repo kökünü bulur.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod bulunamadı (repo kökü)")
		}
		dir = parent
	}
}

func isAllowed(relDir string) bool {
	for _, a := range allowedBoundaryDirs {
		if relDir == a || strings.HasPrefix(relDir, a+"/") {
			return true
		}
	}
	return false
}

// TestNoRawMutationBypass, G-02 mimari değişmezini korur: raw Store mutasyonları YALNIZ
// bilinen sınır paketlerinde çağrılabilir. Yeni bir üretim paketi bir mutasyonu doğrudan
// çağırırsa bu test (dolayısıyla CI) kırılır — bypass sınıfının kök nedeni yeniden doğamaz.
// Metot ÇAĞRILARI (".Method(") aranır; tanım/impl (`func (s) Method(`) ve _test.go hariç.
func TestNoRawMutationBypass(t *testing.T) {
	root := repoRoot(t)
	serverDir := filepath.Join(root, "server")

	type violation struct{ file, method string }
	var violations []violation

	err := filepath.Walk(serverDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// _demo scratch ağacını atla.
			if info.Name() == "_demo" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		relDir := filepath.ToSlash(rel)
		if isAllowed(relDir) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		src := string(data)
		for _, m := range rawMutationMethods {
			if strings.Contains(src, "."+m+"(") {
				violations = append(violations, violation{filepath.ToSlash(rel) + "/" + info.Name(), m})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(violations) > 0 {
		for _, v := range violations {
			t.Errorf("G-02 bypass: %s raw mutasyon .%s( çağrılıyor — sınır dışı paket; privman/GuardedExecutor üzerinden geçmeli", v.file, v.method)
		}
	}
}
