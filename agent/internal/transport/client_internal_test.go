package transport

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// selfSignedPEM, kendinden imzalı bir sertifika + eşleşen özel anahtar PEM'i üretir
// (tls.X509KeyPair için geçerli çift).
func selfSignedPEM(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "unit-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestGenerateKeyAndCSR(t *testing.T) {
	keyPEM, csrPEM, err := GenerateKeyAndCSR("agent-42")
	if err != nil {
		t.Fatal(err)
	}

	// CSR PEM ayrıştırılabilmeli ve CN korunmalı.
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("CSR PEM bloğu geçersiz: %+v", block)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("CSR ayrıştırılamadı: %v", err)
	}
	if csr.Subject.CommonName != "agent-42" {
		t.Fatalf("CN korunmalıydı, %q", csr.Subject.CommonName)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR imzası geçerli olmalı: %v", err)
	}

	// Anahtar PEM PKCS8 EC anahtarı olmalı.
	kb, _ := pem.Decode(keyPEM)
	if kb == nil || kb.Type != "PRIVATE KEY" {
		t.Fatalf("anahtar PEM bloğu geçersiz: %+v", kb)
	}
	priv, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatalf("özel anahtar ayrıştırılamadı: %v", err)
	}
	if _, ok := priv.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("EC özel anahtar beklenirdi, %T", priv)
	}
}

func TestNewCertHolder(t *testing.T) {
	certPEM, keyPEM := selfSignedPEM(t)

	h, err := NewCertHolder(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	cur := h.current()
	if cur == nil {
		t.Fatal("current nil olmamalı")
	}
	if len(cur.Certificate) == 0 {
		t.Fatal("tutulan sertifika boş")
	}
}

func TestNewCertHolderBadPEM(t *testing.T) {
	if _, err := NewCertHolder([]byte("cert değil"), []byte("key değil")); err == nil {
		t.Fatal("geçersiz cert/key PEM reddedilmeliydi")
	}
}

func TestCertHolderSet(t *testing.T) {
	certPEM, keyPEM := selfSignedPEM(t)
	h, err := NewCertHolder(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	first := h.current()

	// Yenileme sonrası yeni cert+key ile değiştir.
	cert2PEM, key2PEM := selfSignedPEM(t)
	if err := h.Set(cert2PEM, key2PEM); err != nil {
		t.Fatal(err)
	}
	second := h.current()
	if second == nil {
		t.Fatal("Set sonrası current nil olmamalı")
	}
	if bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Fatal("Set tutulan sertifikayı değiştirmeliydi")
	}
}

func TestCertHolderSetBadPEM(t *testing.T) {
	certPEM, keyPEM := selfSignedPEM(t)
	h, err := NewCertHolder(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Set([]byte("bozuk"), []byte("bozuk")); err == nil {
		t.Fatal("geçersiz PEM ile Set hata dönmeliydi")
	}
	// Başarısız Set eski sertifikayı korumalı.
	if h.current() == nil {
		t.Fatal("başarısız Set sonrası eski sertifika korunmalıydı")
	}
}

func TestTLSConfig(t *testing.T) {
	certPEM, keyPEM := selfSignedPEM(t)
	h, err := NewCertHolder(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	// caPEM olarak geçerli bir sertifika PEM'i kullan (CertPool'a yüklenebilir).
	caPEM, _ := selfSignedPEM(t)
	cfg, err := h.tlsConfig(caPEM, "c2.example")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "c2.example" {
		t.Fatalf("ServerName ayarlanmalıydı, %q", cfg.ServerName)
	}
	if cfg.MinVersion != 0x0304 { // TLS 1.3
		t.Fatalf("TLS 1.3 minimum beklenirdi, %x", cfg.MinVersion)
	}
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs ayarlanmalıydı")
	}
	// GetClientCertificate holder'dan güncel sertifikayı okumalı.
	got, err := cfg.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != h.current() {
		t.Fatal("GetClientCertificate holder'dan güncel sertifikayı dönmeliydi")
	}
}

func TestTLSConfigBadCA(t *testing.T) {
	certPEM, keyPEM := selfSignedPEM(t)
	h, err := NewCertHolder(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.tlsConfig([]byte("CA değil"), "c2"); err == nil {
		t.Fatal("geçersiz CA zinciri reddedilmeliydi")
	}
}

func TestSetServerPinsTrimAndEmpty(t *testing.T) {
	t.Cleanup(func() { SetServerPins(nil) })

	// Boşluklu ve boş girdiler temizlenmeli.
	SetServerPins([]string{"  pinA  ", "", "   ", "pinB"})
	p := serverPins.Load()
	if p == nil {
		t.Fatal("pin listesi saklanmalıydı")
	}
	if len(*p) != 2 || (*p)[0] != "pinA" || (*p)[1] != "pinB" {
		t.Fatalf("trim/boş temizleme yanlış: %v", *p)
	}
	// Temizlenmiş liste ayarlıyken verifier olmalı.
	if pinVerifier() == nil {
		t.Fatal("pin ayarlıyken verifier olmalı")
	}

	// Tümü boş → verifier nil (pinning devre dışı).
	SetServerPins([]string{"", "   "})
	if pinVerifier() != nil {
		t.Fatal("tüm pinler boşsa pinning devre dışı olmalı")
	}
}
