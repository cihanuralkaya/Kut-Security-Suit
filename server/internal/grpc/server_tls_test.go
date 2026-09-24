package grpc

import (
	"crypto/tls"
	"testing"

	"kut.corp/suite/server/internal/revocation"
)

// TestBuildTLSSuccess, geçerli sunucu sertifika/anahtar ve istemci-CA ile mTLS
// yapılandırmasının kurulduğunu doğrular (RequireAndVerifyClientCert → ClientCA yüklenir).
func TestBuildTLSSuccess(t *testing.T) {
	cert, key := genSelfSigned(t)
	ca, _ := genSelfSigned(t)
	cfg, err := buildTLS(TLSMaterial{
		ServerCertPEM: cert, ServerKeyPEM: key, ClientCAPEM: ca,
	}, tls.RequireAndVerifyClientCert)
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion TLS1.3 olmalı, %x", cfg.MinVersion)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth yanlış: %v", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Error("mTLS modunda ClientCAs yüklenmeliydi")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("1 sunucu sertifikası beklenirdi, %d", len(cfg.Certificates))
	}
}

// TestBuildTLSWithRevocation, Revocation verildiğinde VerifyPeerCertificate
// kancasının kurulduğunu doğrular (iptal kontrolü zincir doğrulamasına EKlenir).
func TestBuildTLSWithRevocation(t *testing.T) {
	cert, key := genSelfSigned(t)
	ca, _ := genSelfSigned(t)
	cfg, err := buildTLS(TLSMaterial{
		ServerCertPEM: cert, ServerKeyPEM: key, ClientCAPEM: ca,
		Revocation: revocation.NewCache(),
	}, tls.RequireAndVerifyClientCert)
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Error("Revocation verilince VerifyPeerCertificate kancası kurulmalıydı")
	}
}

// TestBuildTLSBadServerCert, bozuk sunucu sertifika/anahtar PEM'inde hata dönmeli.
func TestBuildTLSBadServerCert(t *testing.T) {
	if _, err := buildTLS(TLSMaterial{
		ServerCertPEM: []byte("bozuk"), ServerKeyPEM: []byte("bozuk"),
	}, tls.RequireAndVerifyClientCert); err == nil {
		t.Fatal("bozuk sunucu sertifika/anahtarında hata beklenirdi")
	}
}

// TestBuildTLSBadClientCA, bozuk istemci-CA PEM'inde hata dönmeli.
func TestBuildTLSBadClientCA(t *testing.T) {
	cert, key := genSelfSigned(t)
	if _, err := buildTLS(TLSMaterial{
		ServerCertPEM: cert, ServerKeyPEM: key, ClientCAPEM: []byte("bozuk-ca"),
	}, tls.RequireAndVerifyClientCert); err == nil {
		t.Fatal("bozuk istemci-CA PEM'inde hata beklenirdi")
	}
}

// TestBuildTLSNoClientCert, NoClientCert modunda ClientCA yüklenmemeli (istemci
// sertifikası hiç okunmaz) ve boş/bozuk ClientCAPEM sorun çıkarmamalı.
func TestBuildTLSNoClientCert(t *testing.T) {
	cert, key := genSelfSigned(t)
	cfg, err := buildTLS(TLSMaterial{
		ServerCertPEM: cert, ServerKeyPEM: key, ClientCAPEM: nil,
	}, tls.NoClientCert)
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if cfg.ClientCAs != nil {
		t.Error("NoClientCert modunda ClientCAs yüklenmemeliydi")
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth NoClientCert olmalı, %v", cfg.ClientAuth)
	}
}

// TestNewAgentServer, kendinden imzalı TLS malzemesiyle mTLS AgentService
// sunucusunun kurulduğunu doğrular (Serve çağrılmaz — bloklar).
func TestNewAgentServer(t *testing.T) {
	cert, key := genSelfSigned(t)
	ca, _ := genSelfSigned(t)
	s, err := NewAgentServer(TLSMaterial{
		ServerCertPEM: cert, ServerKeyPEM: key, ClientCAPEM: ca,
	}, &AgentHandler{})
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if s == nil {
		t.Fatal("sunucu nil dönmemeliydi")
	}
	s.Stop()
}

// TestNewAgentServerBadMaterial, bozuk TLS malzemesiyle NewAgentServer hata dönmeli.
func TestNewAgentServerBadMaterial(t *testing.T) {
	if _, err := NewAgentServer(TLSMaterial{
		ServerCertPEM: []byte("x"), ServerKeyPEM: []byte("y"),
	}, &AgentHandler{}); err == nil {
		t.Fatal("bozuk malzemede hata beklenirdi")
	}
}

// TestNewEnrollServer, EnrollmentService sunucusunun kurulduğunu doğrular
// (VerifyClientCertIfGiven → ClientCA yüklenir).
func TestNewEnrollServer(t *testing.T) {
	cert, key := genSelfSigned(t)
	ca, _ := genSelfSigned(t)
	s, err := NewEnrollServer(TLSMaterial{
		ServerCertPEM: cert, ServerKeyPEM: key, ClientCAPEM: ca,
	}, &EnrollmentHandler{})
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if s == nil {
		t.Fatal("sunucu nil dönmemeliydi")
	}
	s.Stop()
}

// TestNewEnrollServerBadMaterial, bozuk TLS malzemesiyle NewEnrollServer hata dönmeli.
func TestNewEnrollServerBadMaterial(t *testing.T) {
	if _, err := NewEnrollServer(TLSMaterial{
		ServerCertPEM: []byte("x"), ServerKeyPEM: []byte("y"),
	}, &EnrollmentHandler{}); err == nil {
		t.Fatal("bozuk malzemede hata beklenirdi")
	}
}
