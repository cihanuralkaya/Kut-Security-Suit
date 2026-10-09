package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"

	"kut.corp/suite/server/internal/security"
)

type fakeCreds struct {
	adminID, hash string
	err           error
}

func (f fakeCreds) LookupAdmin(ctx context.Context, email string) (string, string, error) {
	return f.adminID, f.hash, f.err
}

type fakeMFA struct {
	secret       string
	enrolled     bool
	lookupErr    error
	consumeOK    bool
	consumeErr   error
	consumeCalls int
}

func (f *fakeMFA) LookupMFA(ctx context.Context, adminID string) (string, bool, error) {
	return f.secret, f.enrolled, f.lookupErr
}

func (f *fakeMFA) ConsumeTOTPStep(ctx context.Context, adminID string, step int64) (bool, error) {
	f.consumeCalls++
	return f.consumeOK, f.consumeErr
}

func mustHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := security.HashPassword(pw)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return h
}

func TestAuthenticator_PasswordOnly(t *testing.T) {
	dummy := mustHash(t, "dummy")
	auth := NewAuthenticator(fakeCreds{adminID: "a1", hash: mustHash(t, "s3cret")}, nil, dummy, nil)
	ctx := context.Background()

	if r, _ := auth.Authenticate(ctx, "a@x", "s3cret", ""); r.Status != AuthOK || r.AdminID != "a1" {
		t.Errorf("doğru parola AuthOK vermeli: %+v", r)
	}
	if r, _ := auth.Authenticate(ctx, "a@x", "wrong", ""); r.Status != AuthInvalid {
		t.Errorf("yanlış parola AuthInvalid vermeli: %+v", r)
	}
}

func TestAuthenticator_UnknownAccountConstantTime(t *testing.T) {
	// adminID boş → bilinmeyen hesap; kukla hash ile sabit-zaman, AuthInvalid.
	auth := NewAuthenticator(fakeCreds{adminID: "", hash: ""}, nil, mustHash(t, "dummy"), nil)
	if r, err := auth.Authenticate(context.Background(), "nobody@x", "whatever", ""); err != nil || r.Status != AuthInvalid {
		t.Errorf("bilinmeyen hesap AuthInvalid vermeli: %+v err=%v", r, err)
	}
}

func TestAuthenticator_LookupErrorPropagates(t *testing.T) {
	auth := NewAuthenticator(fakeCreds{err: errors.New("db down")}, nil, mustHash(t, "dummy"), nil)
	if _, err := auth.Authenticate(context.Background(), "a@x", "p", ""); err == nil {
		t.Error("altyapı hatası yukarı taşınmalıydı")
	}
}

func TestAuthenticator_MFAFlow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	secret, err := security.GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	code, err := security.TOTPAt(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	creds := fakeCreds{adminID: "a1", hash: mustHash(t, "pw")}
	clock := func() time.Time { return now }

	// Enrolled, kod yok → MFARequired (başarısızlık DEĞİL).
	mfa := &fakeMFA{secret: secret, enrolled: true, consumeOK: true}
	auth := NewAuthenticator(creds, mfa, mustHash(t, "dummy"), clock)
	if r, _ := auth.Authenticate(context.Background(), "a@x", "pw", ""); r.Status != AuthMFARequired {
		t.Errorf("kod yokken MFARequired bekleniyordu: %+v", r)
	}

	// Geçerli kod + tüketim kabul → OK.
	if r, _ := auth.Authenticate(context.Background(), "a@x", "pw", code); r.Status != AuthOK {
		t.Errorf("geçerli kod AuthOK vermeli: %+v", r)
	}

	// Geçersiz kod → MFAInvalidCode.
	if r, _ := auth.Authenticate(context.Background(), "a@x", "pw", "000000"); r.Status != AuthMFAInvalidCode {
		t.Errorf("geçersiz kod AuthMFAInvalidCode vermeli: %+v", r)
	}

	// Geçerli kod ama tüketim reddi (replay) → MFAReplay.
	replay := &fakeMFA{secret: secret, enrolled: true, consumeOK: false}
	authReplay := NewAuthenticator(creds, replay, mustHash(t, "dummy"), clock)
	if r, _ := authReplay.Authenticate(context.Background(), "a@x", "pw", code); r.Status != AuthMFAReplay {
		t.Errorf("tüketilmiş adım AuthMFAReplay vermeli: %+v", r)
	}

	// Enrolled olmayan hesapta MFA atlanır → OK.
	noMFA := &fakeMFA{enrolled: false}
	authNo := NewAuthenticator(creds, noMFA, mustHash(t, "dummy"), clock)
	if r, _ := authNo.Authenticate(context.Background(), "a@x", "pw", ""); r.Status != AuthOK {
		t.Errorf("MFA etkin değilken AuthOK vermeli: %+v", r)
	}
}
