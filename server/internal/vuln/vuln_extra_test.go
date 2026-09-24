package vuln

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadFile, LoadFile'ın geçerli dosyayı yüklediğini ve eksik dosyada hata
// döndürdüğünü doğrular.
func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vuln.json")
	if err := os.WriteFile(path, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Size() != 3 {
		t.Fatalf("3 kayıt beklenirdi, %d", s.Size())
	}

	// Eksik dosya → hata.
	if _, err := LoadFile(filepath.Join(dir, "yok.json")); err == nil {
		t.Error("eksik dosya hata dönmeli")
	}
}

// TestSizeNil, nil *Set üzerinde Size'ın 0 döndürdüğünü doğrular (panik yok).
func TestSizeNil(t *testing.T) {
	var s *Set
	if s.Size() != 0 {
		t.Fatalf("nil set boyutu 0 olmalı, %d", s.Size())
	}
}

// TestMatchSameCVEMultiplePackages, aynı CVE'nin birden çok yüklü pakete uyduğunda
// her biri için ayrı bulgu üretildiğini doğrular.
func TestMatchSameCVEMultiplePackages(t *testing.T) {
	s, err := Load(strings.NewReader(`[{"product":"log4j","cve":"CVE-2021-44228","severity":"CRITICAL"}]`))
	if err != nil {
		t.Fatal(err)
	}
	f := s.Match([]string{"apache-log4j-core", "spring-log4j-bridge", "unrelated-pkg"})
	if len(f) != 2 {
		t.Fatalf("aynı CVE iki pakete uymalı (2 bulgu): %+v", f)
	}
	pkgs := map[string]bool{}
	for _, x := range f {
		if x.CVE != "CVE-2021-44228" {
			t.Fatalf("beklenmeyen CVE: %+v", x)
		}
		pkgs[x.Package] = true
	}
	if !pkgs["apache-log4j-core"] || !pkgs["spring-log4j-bridge"] {
		t.Fatalf("her iki paket de ayrı bildirilmeliydi: %+v", pkgs)
	}
}

// TestMatchMultipleEntriesPerPackage, tek bir paketin veri kümesindeki birden çok
// kayda uyduğunda her kayıt için ayrı bulgu üretildiğini doğrular.
func TestMatchMultipleEntriesPerPackage(t *testing.T) {
	s, err := Load(strings.NewReader(`[
	  {"product":"openssl","cve":"CVE-A","severity":"HIGH"},
	  {"product":"ssl","cve":"CVE-B","severity":"MEDIUM"}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	f := s.Match([]string{"OpenSSL 1.1.1"})
	if len(f) != 2 {
		t.Fatalf("tek paket iki kayda uymalı (2 bulgu): %+v", f)
	}
	seen := map[string]bool{}
	for _, x := range f {
		seen[x.CVE] = true
	}
	if !seen["CVE-A"] || !seen["CVE-B"] {
		t.Fatalf("her iki CVE de bildirilmeliydi: %+v", seen)
	}
}

// TestMatchesEmptyProduct, boş Product'lı bir kaydın hiçbir pakete uymadığını
// doğrular (matches boş-ürün yolu).
func TestMatchesEmptyProduct(t *testing.T) {
	if (Entry{Product: ""}).matches("anything") {
		t.Fatal("boş Product hiçbir pakete uymamalı")
	}
	if !(Entry{Product: "zip"}).matches("7-Zip") {
		t.Fatal("dolu Product alt-dize olarak uymalı")
	}
}
