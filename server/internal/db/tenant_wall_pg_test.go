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
	"kut.corp/suite/server/internal/security"
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

	// NEGATIF (re-home): aynı MAC, başka kiracının token'ı → A'nın satırına DOKUNULMAZ; B kendi
	// AYRI cihazını alır (S-3: tekillik kiracı başına, MAC-squat DoS yok).
	evil := in
	evil.TenantID, evil.HostnameEnc = tB, []byte("EVIL")
	idB, err := s.UpsertEnrollingDevice(ctx, evil)
	if err != nil || idB == id {
		t.Fatalf("çapraz-kiracı kayıt A'nın cihazını devralmamalı, B kendi satırını almalı: id=%q err=%v", idB, err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM devices WHERE id = $1::uuid`, idB) })
	if tn, _ := s.TenantForDevice(ctx, id); tn != tA {
		t.Fatalf("cihaz kiracısı değişmemeli: %q", tn)
	}
	if tn, _ := s.TenantForDevice(ctx, idB); tn != tB {
		t.Fatalf("B cihazı B kiracısında olmalı: %q", tn)
	}
	var host []byte
	if err := s.pool.QueryRow(ctx, `SELECT hostname_encrypted FROM devices WHERE id = $1::uuid`, id).Scan(&host); err != nil || string(host) != "h1" {
		t.Fatalf("diğer kiracının kaydı A'nın alanlarını değiştirmemeli: %q %v", host, err)
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

func devTenant(ctx context.Context, t *testing.T, s *Store, id string) string {
	t.Helper()
	var tn string
	if err := s.pool.QueryRow(ctx, `SELECT tenant_id FROM devices WHERE id = $1::uuid`, id).Scan(&tn); err != nil {
		t.Fatal(err)
	}
	return tn
}

// S-2 (PG): kiracı öncesi (legacy) cihazların tenant_id'si boştur (şema varsayılanı). Örtük
// "default" token'ıyla yeniden kayıt (hem MAC/ON CONFLICT hem PreferredDeviceID yolu)
// reddedilmez ve kiracıyı default'a normalleştirir; gerçek kiracılar için taşıma engelli kalır.
func TestPGLegacyEmptyTenantDeviceReenrollsUnderDefault(t *testing.T) {
	s, ctx := pgStore(t)
	other := uniq(t, "tx-")

	// MAC yolu (ON CONFLICT).
	mac := []byte(uniq(t, "mac-legacy-"))
	in := enroll.DeviceEnrollment{
		MACBlindIndex: mac, HostnameEnc: []byte("old"), MACEnc: []byte("m"), OSInfoEnc: []byte("o"),
		OSPlatform: "linux", AgentVersion: "1", TenantID: "",
	}
	id, err := s.UpsertEnrollingDevice(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM devices WHERE id = $1::uuid`, id) })
	if tn := devTenant(ctx, t, s, id); tn != "" {
		t.Fatalf("legacy cihaz boş kiracıyla başlamalı: %q", tn)
	}

	// NEGATIF: gerçek kiracı legacy cihazı devralamaz: kendi AYRI satırını alır (S-3), legacy
	// satır değişmez.
	evil := in
	evil.TenantID, evil.HostnameEnc = other, []byte("EVIL")
	idO, err := s.UpsertEnrollingDevice(ctx, evil)
	if err != nil || idO == id {
		t.Fatalf("gerçek kiracı legacy cihazı devralamaz, kendi satırını almalı: id=%q err=%v", idO, err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM devices WHERE id = $1::uuid`, idO) })
	if tn := devTenant(ctx, t, s, id); tn != "" {
		t.Fatalf("diğer kiracının kaydı legacy kiracıyı değiştirmemeli: %q", tn)
	}

	// POZITIF: "default" token'ı aynı cihazı günceller + kiracıyı normalleştirir.
	def := in
	def.TenantID, def.HostnameEnc = "default", []byte("new")
	got, err := s.UpsertEnrollingDevice(ctx, def)
	if err != nil || got != id {
		t.Fatalf("default token'ı legacy cihazı yeniden kaydetmeli: %q %v", got, err)
	}
	if tn := devTenant(ctx, t, s, id); tn != "default" {
		t.Fatalf("kiracı default'a normalleşmeli: %q", tn)
	}
	var host []byte
	if err := s.pool.QueryRow(ctx, `SELECT hostname_encrypted FROM devices WHERE id = $1::uuid`, id).Scan(&host); err != nil || string(host) != "new" {
		t.Fatalf("alanlar güncellenmeli: %q %v", host, err)
	}
	// Normalleşmeden sonra da gerçek kiracı için duvar aynı: yine kendi satırını alır.
	if again, err := s.UpsertEnrollingDevice(ctx, evil); err != nil || again != idO {
		t.Fatalf("normalleşmiş cihaz başka kiracıya taşınamaz, other kendi satırını güncellemeli: %q %v", again, err)
	}

	// PreferredDeviceID yolu: ikinci bir legacy cihaz.
	in2 := in
	in2.MACBlindIndex = []byte(uniq(t, "mac-legacy2-"))
	id2, err := s.UpsertEnrollingDevice(ctx, in2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM devices WHERE id = $1::uuid`, id2) })
	pref := in2
	pref.PreferredDeviceID, pref.TenantID = id2, other
	if _, err := s.UpsertEnrollingDevice(ctx, pref); !errors.Is(err, enroll.ErrTenantMismatch) {
		t.Fatalf("preferred yolunda gerçek kiracı legacy cihazı devralamaz: %v", err)
	}
	pref.TenantID = "default"
	if got, err := s.UpsertEnrollingDevice(ctx, pref); err != nil || got != id2 {
		t.Fatalf("preferred yolunda default token'ı geçmeli: %q %v", got, err)
	}
	if tn := devTenant(ctx, t, s, id2); tn != "default" {
		t.Fatalf("preferred yolunda da default'a normalleşmeli: %q", tn)
	}
}

// S-7 (PG): bekleyen sır AYRI sütunda tutulur; ActivateMFA tek UPDATE ile takas yapar;
// bekleyen pencerede etkin sır + enrolled=true korunur; Disable ikisini de temizler.
func TestPGMFAPendingSecretSwap(t *testing.T) {
	s, ctx := pgStore(t)
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	cipher, err := security.NewFieldCipher(security.DeriveKey(master, security.LabelFieldEncryption))
	if err != nil {
		t.Fatal(err)
	}
	s.SetFieldCipher(cipher)

	id, err := s.CreateAdmin(ctx, uniq(t, "mfa-")+"@x", "h", admin.RoleOperator, uniq(t, "tm-"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM admins WHERE id = $1::uuid`, id) })

	look := func(wantSecret string, wantOn bool, wantPending string) {
		t.Helper()
		sec, on, err := s.LookupMFA(ctx, id)
		if err != nil || sec != wantSecret || on != wantOn {
			t.Fatalf("LookupMFA = %q/%v/%v, beklenen %q/%v", sec, on, err, wantSecret, wantOn)
		}
		p, err := s.LookupPendingMFA(ctx, id)
		if err != nil || p != wantPending {
			t.Fatalf("LookupPendingMFA = %q/%v, beklenen %q", p, err, wantPending)
		}
	}

	look("", false, "")
	// Bekleyen sır etkin görünmez.
	if err := s.SetPendingMFASecret(ctx, id, "SECRETONE"); err != nil {
		t.Fatal(err)
	}
	look("", false, "SECRETONE")
	// Bekleyen sırrı etkinleştir (ilk kayıt).
	if err := s.ActivateMFA(ctx, id); err != nil {
		t.Fatal(err)
	}
	look("SECRETONE", true, "")

	// Yeniden kayıt: yeni sır bekleyen kalırken eski sır + enrolled=true AYNEN korunur.
	if err := s.SetPendingMFASecret(ctx, id, "SECRETTWO"); err != nil {
		t.Fatal(err)
	}
	look("SECRETONE", true, "SECRETTWO")
	// Atomik takas: yeni sır etkin, bekleyen temizlenir, eski sır gider.
	if err := s.ActivateMFA(ctx, id); err != nil {
		t.Fatal(err)
	}
	look("SECRETTWO", true, "")
	// Bekleyen yokken tekrar ActivateMFA hiçbir şeyi değiştirmez.
	if err := s.ActivateMFA(ctx, id); err != nil {
		t.Fatal(err)
	}
	look("SECRETTWO", true, "")

	// Disable etkin + bekleyen sırrı temizler.
	if err := s.SetPendingMFASecret(ctx, id, "SECRETTHREE"); err != nil {
		t.Fatal(err)
	}
	if err := s.DisableMFA(ctx, id); err != nil {
		t.Fatal(err)
	}
	look("", false, "")
}

// S-3 (PG): MAC-squat DoS. Kiracı A, B'nin MAC'ini önceden kaydetse bile B kendi cihazını
// enroll edebilir; uq_devices_tenant_mac aynı kiracıda ikinci satırı engeller (kanonik
// kiracı: legacy boş ≡ default); eski küresel kısıt artık yoktur.
func TestPGMACSquatCannotBlockOtherTenant(t *testing.T) {
	s, ctx := pgStore(t)
	evilT, victimT := uniq(t, "tevil-"), uniq(t, "tvic-")
	mac := []byte(uniq(t, "mac-squat-"))
	base := enroll.DeviceEnrollment{
		MACBlindIndex: mac, HostnameEnc: []byte("squat"), MACEnc: []byte("m"), OSInfoEnc: []byte("o"),
		OSPlatform: "linux", AgentVersion: "1", TenantID: evilT,
	}
	squat, err := s.UpsertEnrollingDevice(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM devices WHERE id = $1::uuid`, squat) })

	// NEGATIF (saldırı): squat eden kiracı kurbanın aynı MAC'iyle kurbanı engelleyemez.
	vin := base
	vin.TenantID, vin.HostnameEnc = victimT, []byte("real")
	victim, err := s.UpsertEnrollingDevice(ctx, vin)
	if err != nil {
		t.Fatalf("kurban kiracı aynı MAC ile enroll olabilmeli: %v", err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM devices WHERE id = $1::uuid`, victim) })
	if victim == squat {
		t.Fatal("kurban squat eden kiracının satırını almamalı")
	}
	if tn, _ := s.TenantForDevice(ctx, victim); tn != victimT {
		t.Fatalf("kurban cihazı kurban kiracısında olmalı: %q", tn)
	}
	if tn, _ := s.TenantForDevice(ctx, squat); tn != evilT {
		t.Fatalf("squat satırı değişmemeli: %q", tn)
	}

	// POZITIF: kurban yeniden kaydı kendi satırını günceller (ON CONFLICT yeni hedef).
	vin.HostnameEnc = []byte("real2")
	if again, err := s.UpsertEnrollingDevice(ctx, vin); err != nil || again != victim {
		t.Fatalf("kurban yeniden kaydı kendi satırını güncellemeli: %q %v", again, err)
	}

	// Şema: aynı kiracıda aynı MAC ikinci satır OLAMAZ; farklı kiracıda olabilir; eski küresel
	// tekillik kısıtı yok; yeni indeks var.
	dup := `INSERT INTO devices (hostname_encrypted, mac_address_encrypted, mac_address_bidx, tenant_id)
	        VALUES ('\x01', '\x01', $1, $2)`
	if _, err := s.pool.Exec(ctx, dup, mac, evilT); err == nil {
		t.Fatal("aynı kiracıda aynı MAC için ikinci satır unique ihlali olmalı")
	}
	var oldConstraint, newIndex int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE conname = 'devices_mac_address_bidx_key'`).Scan(&oldConstraint); err != nil {
		t.Fatal(err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE indexname = 'uq_devices_tenant_mac'`).Scan(&newIndex); err != nil {
		t.Fatal(err)
	}
	if oldConstraint != 0 || newIndex != 1 {
		t.Fatalf("eski küresel kısıt kalkmalı (%d), yeni indeks var olmalı (%d)", oldConstraint, newIndex)
	}
}

// S-3 (PG): yükseltme bloğu yeniden çalıştırılabilir (idempotent) — iki kez uygulanınca hata yok.
func TestPGUpgradeBlockIdempotent(t *testing.T) {
	s, ctx := pgStore(t)
	for i := 0; i < 2; i++ {
		for _, stmt := range []string{
			`CREATE UNIQUE INDEX IF NOT EXISTS uq_devices_tenant_mac
			   ON devices ((COALESCE(NULLIF(tenant_id, ''), 'default')), mac_address_bidx)`,
			`ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_mac_address_bidx_key`,
			`ALTER TABLE policies ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(63) NOT NULL DEFAULT ''`,
			`CREATE INDEX IF NOT EXISTS idx_policies_tenant ON policies (tenant_id)`,
		} {
			if _, err := s.pool.Exec(ctx, stmt); err != nil {
				t.Fatalf("yükseltme ifadesi tekrar çalıştırılabilmeli (tur %d): %v\n%s", i, err, stmt)
			}
		}
	}
}
