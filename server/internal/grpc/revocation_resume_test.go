package grpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"kut.corp/suite/server/internal/revocation"
)

// genCertIP, 127.0.0.1 IP SAN'lı kendinden imzalı (CA + sunucu/istemci EKU) bir sertifika
// ile PEM çiftini ve ayrıştırılmış sertifikayı döner.
func genCertIP(t *testing.T, cn string) (certPEM, keyPEM []byte, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<40))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), cert
}

type hsResult struct {
	err    error
	resume bool
}

// resumeHarness, buildTLS ile kurulan bir sunucuya oturum önbellekli istemciyle bağlanır.
type resumeHarness struct {
	t       *testing.T
	results chan hsResult
	addr    string
	cliCfg  *tls.Config
}

func newResumeHarness(t *testing.T, mutate func(*tls.Config), cache *revocation.Cache) *resumeHarness {
	t.Helper()
	srvCertPEM, srvKeyPEM, srvCert := genCertIP(t, "srv")
	cliCertPEM, cliKeyPEM, _ := genCertIP(t, "device-1")
	srvCfg, err := buildTLS(TLSMaterial{
		ServerCertPEM: srvCertPEM, ServerKeyPEM: srvKeyPEM, ClientCAPEM: cliCertPEM, Revocation: cache,
	}, tls.RequireAndVerifyClientCert)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(srvCfg)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	h := &resumeHarness{t: t, results: make(chan hsResult, 8), addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(tc *tls.Conn) {
				defer tc.Close()
				herr := tc.Handshake()
				h.results <- hsResult{err: herr, resume: tc.ConnectionState().DidResume}
				if herr == nil {
					_, _ = tc.Write([]byte("x")) // istemci bileti okusun (TLS1.3 post-handshake)
					_, _ = io.Copy(io.Discard, tc)
				}
			}(c.(*tls.Conn))
		}
	}()
	cliPair, err := tls.X509KeyPair(cliCertPEM, cliKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srvCert)
	h.cliCfg = &tls.Config{
		Certificates:       []tls.Certificate{cliPair},
		RootCAs:            pool,
		MinVersion:         tls.VersionTLS13,
		ClientSessionCache: tls.NewLRUClientSessionCache(4),
	}
	return h
}

// connect, bir bağlantı dener; sunucunun gördüğü el sıkışma sonucunu ve istemcinin
// devam (resumption) teklif edip etmediğini döner.
func (h *resumeHarness) connect() (srv hsResult, clientResumed bool) {
	h.t.Helper()
	conn, err := tls.Dial("tcp", h.addr, h.cliCfg)
	if err == nil {
		clientResumed = conn.ConnectionState().DidResume
		buf := make([]byte, 1)
		_, _ = conn.Read(buf) // TLS1.3: bileti işler / sunucu reddini görür
		_ = conn.Close()
	}
	select {
	case srv = <-h.results:
	case <-time.After(5 * time.Second):
		h.t.Fatal("sunucu el sıkışma sonucu zaman aşımı")
	}
	return srv, clientResumed
}

// TestRevokedCertRejectedOnResumedSession, Z3-04/Z4b-06: iptal kontrolü YALNIZ
// VerifyPeerCertificate'te olursa Go oturum devamında onu çağırmaz ve iptal edilmiş
// sertifika eski bilet ile yeniden bağlanır. VerifyConnection her el sıkışmada çalışır.
func TestRevokedCertRejectedOnResumedSession(t *testing.T) {
	cache := revocation.NewCache()
	h := newResumeHarness(t, nil, cache)

	// 1) tam el sıkışma: kabul, devam yok.
	if r, _ := h.connect(); r.err != nil || r.resume {
		t.Fatalf("ilk bağlantı tam el sıkışma ve başarılı olmalıydı: %+v", r)
	}
	// 2) sertifika iptal EDİLMEMİŞKEN devam çalışmalı (testin anlamlı olduğunun kanıtı).
	r, clientResumed := h.connect()
	if r.err != nil || !r.resume || !clientResumed {
		t.Fatalf("iptalsiz ikinci bağlantı devam etmeliydi (server=%+v clientResumed=%v)", r, clientResumed)
	}
	// 3) sertifikayı iptal et: bilet hâlâ geçerli ama bağlantı REDDEDİLMELİ.
	leaf := h.cliCfg.Certificates[0].Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(h.cliCfg.Certificates[0].Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256(leaf.Raw)
	cache.Replace([][]byte{sum[:]})

	r, clientResumed = h.connect()
	if !clientResumed {
		t.Fatal("test geçersiz: istemci oturum devamı denemedi")
	}
	if r.err == nil {
		t.Fatal("iptal edilmiş sertifika DEVAM EDEN oturumda kabul edildi (revocation bypass)")
	}
	if !errors.Is(r.err, revocation.ErrRevoked) {
		t.Fatalf("ErrRevoked beklenirdi, dönen: %v", r.err)
	}
}

// TestResumedSessionBypassWithoutVerifyConnection, KONTROL: VerifyConnection kaldırılırsa
// (yalnız VerifyPeerCertificate) iptal edilmiş sertifika devam eden oturumda geçer — yani
// düzeltme gereklidir ve test gerçekten bypass'ı yakalar.
func TestResumedSessionBypassWithoutVerifyConnection(t *testing.T) {
	cache := revocation.NewCache()
	h := newResumeHarness(t, func(c *tls.Config) { c.VerifyConnection = nil }, cache)
	if r, _ := h.connect(); r.err != nil {
		t.Fatalf("ilk bağlantı: %v", r.err)
	}
	leaf, err := x509.ParseCertificate(h.cliCfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(leaf.Raw)
	cache.Replace([][]byte{sum[:]})
	r, _ := h.connect()
	if r.err != nil || !r.resume {
		t.Skipf("bu Go sürümü devam eden oturumda sertifikayı yeniden doğruluyor (%+v); kontrol atlandı", r)
	}
}

// TestFreshHandshakeRevokedStillRejected, tam (devam etmeyen) el sıkışmada da iptal reddi sürer.
func TestFreshHandshakeRevokedStillRejected(t *testing.T) {
	cache := revocation.NewCache()
	h := newResumeHarness(t, nil, cache)
	leaf, err := x509.ParseCertificate(h.cliCfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(leaf.Raw)
	cache.Replace([][]byte{sum[:]})
	r, _ := h.connect()
	if !errors.Is(r.err, revocation.ErrRevoked) {
		t.Fatalf("taze el sıkışmada ErrRevoked beklenirdi: %v", r.err)
	}
}
