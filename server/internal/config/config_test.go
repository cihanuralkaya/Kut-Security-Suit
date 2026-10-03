package config

import (
	"encoding/base64"
	"os"
	"runtime"
	"strings"
	"testing"
)

// setValid, geçerli bir yapılandırma için gereken tüm zorunlu env'leri ayarlar.
func setValid(t *testing.T) {
	t.Helper()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	t.Setenv("KUT_MASTER_KEY", key)
	t.Setenv("KUT_CA_CERT", "/x/ca.crt")
	t.Setenv("KUT_CA_KEY", "/x/ca.key")
	t.Setenv("KUT_SERVER_CERT", "/x/s.crt")
	t.Setenv("KUT_SERVER_KEY", "/x/s.key")
}

func TestLoadValid(t *testing.T) {
	setValid(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.MasterKey) != 32 || c.CACertPath == "" {
		t.Fatalf("geçerli config beklenirdi: %+v", c)
	}
}

func TestLoadRejectsMissingMasterKey(t *testing.T) {
	t.Setenv("KUT_MASTER_KEY", "")
	if _, err := Load(); err == nil {
		t.Fatal("eksik master key reddedilmeliydi")
	}
}

func TestLoadRejectsShortMasterKey(t *testing.T) {
	t.Setenv("KUT_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 16)))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "32 bayt") {
		t.Fatalf("kısa master key reddedilmeliydi: %v", err)
	}
}

func TestLoadRejectsMissingTLSPaths(t *testing.T) {
	setValid(t)
	t.Setenv("KUT_SERVER_CERT", "") // birini kaldır
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "KUT_SERVER_CERT") {
		t.Fatalf("eksik TLS yolu reddedilmeliydi: %v", err)
	}
}

func TestLoadRejectsBadNumeric(t *testing.T) {
	setValid(t)
	t.Setenv("KUT_RETENTION_DAYS", "0")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "KUT_RETENTION_DAYS") {
		t.Fatalf("geçersiz saklama günü reddedilmeliydi: %v", err)
	}
}

func TestLoadMasterKeyFromFile(t *testing.T) {
	// TLS materyali + master-key dosyası; env'de KUT_MASTER_KEY YOK, _FILE var.
	t.Setenv("KUT_CA_CERT", "/x/ca.crt")
	t.Setenv("KUT_CA_KEY", "/x/ca.key")
	t.Setenv("KUT_SERVER_CERT", "/x/s.crt")
	t.Setenv("KUT_SERVER_KEY", "/x/s.key")
	t.Setenv("KUT_MASTER_KEY", "")

	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	dir := t.TempDir()
	f := dir + "/mk"
	if err := os.WriteFile(f, []byte(key+"\n"), 0o600); err != nil { // sondaki newline kırpılmalı
		t.Fatal(err)
	}
	t.Setenv("KUT_MASTER_KEY_FILE", f)

	c, err := Load()
	if err != nil {
		t.Fatalf("dosya-tabanlı master key yüklenmeli: %v", err)
	}
	if len(c.MasterKey) != 32 {
		t.Fatalf("32 baytlık anahtar beklenirdi, %d", len(c.MasterKey))
	}
}

func TestLoadMasterKeyFileMissing(t *testing.T) {
	t.Setenv("KUT_CA_CERT", "/x/ca.crt")
	t.Setenv("KUT_CA_KEY", "/x/ca.key")
	t.Setenv("KUT_SERVER_CERT", "/x/s.crt")
	t.Setenv("KUT_SERVER_KEY", "/x/s.key")
	t.Setenv("KUT_MASTER_KEY", "")
	t.Setenv("KUT_MASTER_KEY_FILE", "/nonexistent/mk")
	if _, err := Load(); err == nil {
		t.Fatal("olmayan _FILE dosyası hata vermeli")
	}
}

func TestLoadClearsSecrets(t *testing.T) {
	setValid(t)

	t.Setenv("KUT_DATABASE_URL", "postgres://test")
	t.Setenv("KUT_MASTER_KEY_OLD", base64.StdEncoding.EncodeToString(make([]byte, 32)))

	_, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	secrets := []string{
		"KUT_MASTER_KEY",
		"KUT_MASTER_KEY_FILE",
		"KUT_MASTER_KEY_OLD",
		"KUT_MASTER_KEY_OLD_FILE",
		"KUT_DATABASE_URL",
		"KUT_DATABASE_URL_FILE",
	}

	for _, s := range secrets {
		if val, exists := os.LookupEnv(s); exists {
			t.Errorf("sır temizlenmedi, %s = %s", s, val)
		}
	}
}

func TestCheckKeyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows testlerinde POSIX izinleri atlanıyor")
	}

	dir := t.TempDir()

	// 1. Çok açık izin (0644)
	badPath := dir + "/bad.key"
	if err := os.WriteFile(badPath, []byte("key"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := checkKeyPermissions(badPath)
	if err == nil {
		t.Fatal("0644 izinli dosya için hata dönmeliydi")
	}
	if !strings.Contains(err.Error(), "çok açık") {
		t.Fatalf("beklenmeyen hata mesajı: %v", err)
	}

	// 2. Güvenli izin (0600)
	goodPath := dir + "/good.key"
	if err := os.WriteFile(goodPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := checkKeyPermissions(goodPath); err != nil {
		t.Fatalf("0600 izinli dosya için hata dönmemeliydi: %v", err)
	}
}

func TestLoadStrictKeyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows testlerinde POSIX izinleri atlanıyor")
	}
	setValid(t)

	dir := t.TempDir()
	caPath := dir + "/ca.key"
	if err := os.WriteFile(caPath, []byte("key"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUT_CA_KEY", caPath)
	
	serverPath := dir + "/server.key"
	if err := os.WriteFile(serverPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUT_SERVER_KEY", serverPath)

	// Varsayılan: uyarı verir ama hata dönmez
	t.Setenv("KUT_STRICT_KEY_PERMISSIONS", "")
	if _, err := Load(); err != nil {
		t.Fatalf("strict mod kapalıyken hata dönmemeli: %v", err)
	}

	// Strict mod açık
	t.Setenv("KUT_STRICT_KEY_PERMISSIONS", "1")
	if _, err := Load(); err == nil {
		t.Fatal("strict mod açıkken hata dönmeliydi")
	}
}
