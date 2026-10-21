package enroll

import (
	"context"
	"errors"
	"testing"
)

// mismatchStore, UpsertEnrollingDevice'ta kiracı uyuşmazlığı bildiren bir depodur
// (başka kiracıya ait cihaz).
type mismatchStore struct{ *memStore }

func (m *mismatchStore) UpsertEnrollingDevice(_ context.Context, _ DeviceEnrollment) (string, error) {
	return "", ErrTenantMismatch
}

// Z4b-02: depo kiracı uyuşmazlığı bildirirse Enroll başarısız olur ve HİÇBİR sertifika
// imzalanmaz/kaydedilmez (cihaz devralma yolu kapalı).
func TestEnrollTenantMismatchIssuesNoCertificate(t *testing.T) {
	base := newMemStore()
	svc, bidx := newTestService(t, &mismatchStore{base})
	base.addToken(bidx.Compute("enroll-token:TOK-X"), "")

	_, err := svc.Enroll(context.Background(), Input{
		Token: "TOK-X", CSRPEM: makeCSR(t), Hostname: "H", MACAddress: "AA:BB:CC:DD:EE:FF", OSInfo: "os",
	})
	if !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("ErrTenantMismatch beklenirdi: %v", err)
	}
	if len(base.certs) != 0 {
		t.Fatalf("reddedilen kayıtta sertifika kaydedilmemeli: %d", len(base.certs))
	}
}
