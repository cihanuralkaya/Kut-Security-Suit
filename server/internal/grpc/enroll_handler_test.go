package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	kutv1 "kut.corp/suite/gen/kut/v1"
	"kut.corp/suite/server/internal/enroll"
	"kut.corp/suite/server/internal/security"
)

// enrollMemStore, enroll.Store'un bellek-içi sahtesidir (handler testleri için).
type enrollMemStore struct {
	tokens  map[string]string
	used    map[string]bool
	certs   []enroll.CertRecord
	revoked map[string]bool
	seq     int
}

func newEnrollMemStore() *enrollMemStore {
	return &enrollMemStore{tokens: map[string]string{}, used: map[string]bool{}, revoked: map[string]bool{}}
}

func (m *enrollMemStore) ConsumeEnrollmentToken(_ context.Context, tokenIndex []byte, _ time.Time) (string, string, error) {
	k := string(tokenIndex)
	if m.used[k] {
		return "", "", enroll.ErrInvalidToken
	}
	bound, ok := m.tokens[k]
	if !ok {
		return "", "", enroll.ErrInvalidToken
	}
	m.used[k] = true
	return bound, "", nil
}
func (m *enrollMemStore) UpsertEnrollingDevice(_ context.Context, in enroll.DeviceEnrollment) (string, error) {
	if in.PreferredDeviceID != "" {
		return in.PreferredDeviceID, nil
	}
	m.seq++
	return "device-" + string(rune('A'+m.seq-1)), nil
}
func (m *enrollMemStore) SaveCertificate(_ context.Context, c enroll.CertRecord) error {
	m.certs = append(m.certs, c)
	return nil
}
func (m *enrollMemStore) DeviceHasActiveCert(_ context.Context, deviceID string) (bool, error) {
	if m.revoked[deviceID] {
		return false, nil
	}
	for _, c := range m.certs {
		if c.DeviceID == deviceID {
			return true, nil
		}
	}
	return false, nil
}

func buildEnrollService(t *testing.T, store enroll.Store) (*enroll.Service, *security.BlindIndexer) {
	t.Helper()
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	bidx := security.NewBlindIndexer(security.DeriveKey(master, security.LabelBlindIndex))
	cipher, err := security.NewFieldCipher(security.DeriveKey(master, security.LabelFieldEncryption))
	if err != nil {
		t.Fatal(err)
	}
	ca, caChain := newEnrollCA(t)
	return enroll.NewService(store, ca, bidx, cipher, caChain, time.Hour), bidx
}

func newEnrollCA(t *testing.T) (*security.CA, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "KUT Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	ca, err := security.LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return ca, certPEM
}

func makeCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "agent"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestEnrollHandlerSuccess(t *testing.T) {
	store := newEnrollMemStore()
	svc, bidx := buildEnrollService(t, store)
	store.tokens[string(bidx.Compute("enroll-token:TOK-1"))] = "device-fixed"
	h := NewEnrollmentHandler(svc)

	res, err := h.Enroll(context.Background(), &kutv1.EnrollRequest{
		EnrollmentToken: "TOK-1",
		CsrPem:          makeCSR(t),
		Hostname:        "WS-1",
		MacAddress:      "AA:BB:CC:DD:EE:FF",
		OsInfo:          "Windows 11",
	})
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if res.GetDeviceId() != "device-fixed" {
		t.Errorf("device id = %q, beklenen device-fixed", res.GetDeviceId())
	}
	if len(res.GetClientCertPem()) == 0 {
		t.Error("istemci sertifikası dönmeliydi")
	}
	if res.GetCertNotAfter() == nil {
		t.Error("CertNotAfter dolu olmalı")
	}
}

func TestEnrollHandlerInvalidToken(t *testing.T) {
	store := newEnrollMemStore() // token yok
	svc, _ := buildEnrollService(t, store)
	h := NewEnrollmentHandler(svc)

	_, err := h.Enroll(context.Background(), &kutv1.EnrollRequest{
		EnrollmentToken: "YOK", CsrPem: makeCSR(t),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ErrInvalidToken → PermissionDenied beklenirdi, dönen: %v", err)
	}
}

func TestEnrollHandlerGenericError(t *testing.T) {
	store := newEnrollMemStore()
	svc, _ := buildEnrollService(t, store)
	h := NewEnrollmentHandler(svc)

	// Boş CSR → jenerik hata ("enroll: CSR boş") → Internal.
	_, err := h.Enroll(context.Background(), &kutv1.EnrollRequest{
		EnrollmentToken: "TOK-1", CsrPem: nil,
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("jenerik hata → Internal beklenirdi, dönen: %v", err)
	}
}

func TestRenewCertificateNoPeer(t *testing.T) {
	store := newEnrollMemStore()
	svc, _ := buildEnrollService(t, store)
	h := NewEnrollmentHandler(svc)

	_, err := h.RenewCertificate(context.Background(), &kutv1.RenewRequest{CsrPem: makeCSR(t)})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("peer yokken Unauthenticated beklenirdi, dönen: %v", err)
	}
}

func TestRenewCertificateSuccess(t *testing.T) {
	store := newEnrollMemStore()
	svc, _ := buildEnrollService(t, store)
	// dev-1'in aktif sertifikası olsun (yenileme iptal kontrolü geçsin).
	_ = store.SaveCertificate(context.Background(), enroll.CertRecord{DeviceID: "dev-1", Serial: "1"})
	h := NewEnrollmentHandler(svc)

	res, err := h.RenewCertificate(peerCtx("dev-1"), &kutv1.RenewRequest{CsrPem: makeCSR(t)})
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if res.GetDeviceId() != "dev-1" {
		t.Errorf("device id = %q, beklenen dev-1", res.GetDeviceId())
	}
	if len(res.GetClientCertPem()) == 0 {
		t.Error("yenilenen sertifika dönmeliydi")
	}
}

func TestRenewCertificateRevoked(t *testing.T) {
	store := newEnrollMemStore()
	svc, _ := buildEnrollService(t, store)
	store.revoked["dev-1"] = true // aktif sertifikası yok
	h := NewEnrollmentHandler(svc)

	_, err := h.RenewCertificate(peerCtx("dev-1"), &kutv1.RenewRequest{CsrPem: makeCSR(t)})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ErrDeviceRevoked → PermissionDenied beklenirdi, dönen: %v", err)
	}
}

func TestRenewCertificateGenericError(t *testing.T) {
	store := newEnrollMemStore()
	svc, _ := buildEnrollService(t, store)
	h := NewEnrollmentHandler(svc)

	// Boş CSR → jenerik hata → Internal (peer geçerli).
	_, err := h.RenewCertificate(peerCtx("dev-1"), &kutv1.RenewRequest{CsrPem: nil})
	if status.Code(err) != codes.Internal {
		t.Fatalf("jenerik hata → Internal beklenirdi, dönen: %v", err)
	}
}
