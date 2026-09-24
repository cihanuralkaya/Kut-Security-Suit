package certrenew

import (
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

func TestParseValidity(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nb := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	na := nb.AddDate(0, 0, 30)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "agent"},
		NotBefore:    nb,
		NotAfter:     na,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	gotNB, gotNA, err := ParseValidity(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !gotNB.Equal(nb) {
		t.Errorf("NotBefore=%v, beklenen %v", gotNB, nb)
	}
	if !gotNA.Equal(na) {
		t.Errorf("NotAfter=%v, beklenen %v", gotNA, na)
	}
}

func TestParseValidityBadPEM(t *testing.T) {
	if _, _, err := ParseValidity([]byte("bu PEM değil")); err == nil {
		t.Fatal("geçersiz PEM reddedilmeliydi")
	}
}

func TestParseValidityBadDER(t *testing.T) {
	// Geçerli PEM zarfı ama içi geçersiz DER → ParseCertificate hatası.
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("çöp")})
	if _, _, err := ParseValidity(bad); err == nil {
		t.Fatal("geçersiz DER reddedilmeliydi")
	}
}
