package db

// Gerçek PostgreSQL'e karşı kiracı-duvarı entegrasyon testleri. KUT_DATABASE_URL yoksa
// ATLANIR (CI'daki "DB yolu (PostgreSQL)" işi şemayı yükleyip bu testleri koşturur).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/enroll"
)

func pgStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	dsn := os.Getenv("KUT_DATABASE_URL")
	if dsn == "" {
		t.Skip("KUT_DATABASE_URL yok — PostgreSQL entegrasyon testi atlandı")
	}
	ctx := context.Background()
	s, err := New(ctx, dsn)
	if err != nil {
		t.Fatalf("db bağlantısı: %v", err)
	}
	t.Cleanup(s.Close)
	return s, ctx
}

func uniq(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return prefix + hex.EncodeToString(b)
}

func devStatus(ctx context.Context, t *testing.T, s *Store, id string) string {
	t.Helper()
	var st string
	if err := s.pool.QueryRow(ctx, `SELECT status::text FROM devices WHERE id = $1::uuid`, id).Scan(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

// Z4b-02 (PG): ON CONFLICT yolu cihazı kiracılar arası TAŞIMAZ ve karantinayı ACTIVE'e düşürmez.
func TestPGEnrollTenantWallAndStatusKept(t *testing.T) {
	s, ctx := pgStore(t)
	tA, tB := uniq(t, "ta-"), uniq(t, "tb-")
	mac := []byte(uniq(t, "mac-"))

	in := enroll.DeviceEnrollment{
		MACBlindIndex: mac, HostnameEnc: []byte("h1"), MACEnc: []byte("m"), OSInfoEnc: []byte("o"),
		OSPlatform: "linux", AgentVersion: "1", TenantID: tA,
	}
	id, err := s.UpsertEnrollingDevice(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM devices WHERE id = $1::uuid`, id) })

	// NEGATIF: aynı MAC, başka kiracının token'ı → ErrTenantMismatch; satır değişmez.
	evil := in
	evil.TenantID, evil.HostnameEnc = tB, []byte("EVIL")
	if _, err := s.UpsertEnrollingDevice(ctx, evil); !errors.Is(err, enroll.ErrTenantMismatch) {
		t.Fatalf("çapraz-kiracı yeniden kayıt ErrTenantMismatch olmalı: %v", err)
	}
	if tn, _ := s.TenantForDevice(ctx, id); tn != tA {
		t.Fatalf("cihaz kiracısı değişmemeli: %q", tn)
	}
	var host []byte
	if err := s.pool.QueryRow(ctx, `SELECT hostname_encrypted FROM devices WHERE id = $1::uuid`, id).Scan(&host); err != nil || string(host) != "h1" {
		t.Fatalf("reddedilen kayıt alanları değiştirmemeli: %q %v", host, err)
	}

	// NEGATIF: token'a bağlı cihaz (PreferredDeviceID) yolu da kiracı duvarına tabi.
	pref := in
	pref.PreferredDeviceID, pref.TenantID = id, tB
	if _, err := s.UpsertEnrollingDevice(ctx, pref); !errors.Is(err, enroll.ErrTenantMismatch) {
		t.Fatalf("preferred çapraz-kiracı ErrTenantMismatch olmalı: %v", err)
	}
	if tn, _ := s.TenantForDevice(ctx, id); tn != tA {
		t.Fatalf("preferred yolu kiracıyı değiştirmemeli: %q", tn)
	}

	// Karantina durumları yeniden kayıtla KORUNUR.
	for _, keep := range []string{"QUARANTINED", "QUARANTINE_PENDING", "ACTIVE"} {
		if err := s.SetDeviceStatus(ctx, id, keep); err != nil {
			t.Fatal(err)
		}
		in.HostnameEnc = []byte("h-" + keep)
		if got, err := s.UpsertEnrollingDevice(ctx, in); err != nil || got != id {
			t.Fatalf("aynı kiracıda yeniden kayıt aynı cihaz olmalı: %q %v", got, err)
		}
		if st := devStatus(ctx, t, s, id); st != keep {
			t.Fatalf("yeniden kayıt %s durumunu korumalı, dönen %s", keep, st)
		}
	}
	// POZITIF: OFFLINE / UNINSTALLED → ACTIVE.
	for _, from := range []string{"OFFLINE", "UNINSTALLED"} {
		_ = s.SetDeviceStatus(ctx, id, from)
		if _, err := s.UpsertEnrollingDevice(ctx, in); err != nil {
			t.Fatal(err)
		}
		if st := devStatus(ctx, t, s, id); st != "ACTIVE" {
			t.Fatalf("%s cihaz yeniden kayıtla ACTIVE olmalı, dönen %s", from, st)
		}
	}
	// POZITIF: preferred + aynı kiracı geçer.
	pref.TenantID = tA
	if got, err := s.UpsertEnrollingDevice(ctx, pref); err != nil || got != id {
		t.Fatalf("preferred aynı kiracı geçmeli: %q %v", got, err)
	}
	// Bilinmeyen preferred cihaz: eski "yok" hatası (ErrTenantMismatch DEĞİL).
	pref.PreferredDeviceID = "00000000-0000-0000-0000-000000000001"
	if _, err := s.UpsertEnrollingDevice(ctx, pref); err == nil || errors.Is(err, enroll.ErrTenantMismatch) {
		t.Fatalf("var olmayan cihaz için genel hata beklenirdi: %v", err)
	}
}

// Z4b-10 / Z4a-01 (PG): token kiracı sorgusu ve kiracı süzmeli yönetici listesi.
func TestPGTokenTenantAndAdminListScoped(t *testing.T) {
	s, ctx := pgStore(t)
	tA, tB := uniq(t, "ta-"), uniq(t, "tb-")

	if err := s.SaveEnrollmentToken(ctx, []byte(uniq(t, "tok-")), "", tA, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListEnrollmentTokens(ctx, 5, tA)
	if err != nil || len(rows) == 0 {
		t.Fatalf("token listelenmeli: %v %v", rows, err)
	}
	got, found, err := s.EnrollmentTokenTenant(ctx, rows[0].ID)
	if err != nil || !found || got != tA {
		t.Fatalf("token kiracısı %q olmalı: %q found=%v err=%v", tA, got, found, err)
	}
	if _, found, err := s.EnrollmentTokenTenant(ctx, "bu-bir-uuid-degil"); err != nil || found {
		t.Fatalf("geçersiz id found=false, hata yok olmalı: found=%v err=%v", found, err)
	}

	emailA, emailB := uniq(t, "a-")+"@x", uniq(t, "b-")+"@x"
	if _, err := s.CreateAdmin(ctx, emailA, "h", admin.RoleAdmin, tA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAdmin(ctx, emailB, "h", admin.RoleAdmin, tB); err != nil {
		t.Fatal(err)
	}
	listA, err := s.ListAdmins(ctx, tA)
	if err != nil || len(listA) != 1 || listA[0].Email != emailA {
		t.Fatalf("yalnız %s kiracısının yöneticisi beklenirdi: %+v %v", tA, listA, err)
	}
}
