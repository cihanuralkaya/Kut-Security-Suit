package memstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"kut.corp/suite/server/internal/enroll"
)

// Z4b-02: bir kiracının token'ı, başka kiracıya ait cihazı (aynı MAC blind index)
// devralamaz; cihaz satırı değişmez.
func TestEnrollCannotRehomeDeviceAcrossTenants(t *testing.T) {
	ctx := context.Background()
	s := New()
	idA, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
		MACBlindIndex: []byte("mac-1"), HostnameEnc: []byte("host-A"), TenantID: "acme",
	})
	if err != nil {
		t.Fatal(err)
	}

	// NEGATIF: globex token'ı ile aynı MAC → reddedilir.
	_, err = s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
		MACBlindIndex: []byte("mac-1"), HostnameEnc: []byte("host-EVIL"), TenantID: "globex",
	})
	if !errors.Is(err, enroll.ErrTenantMismatch) {
		t.Fatalf("çapraz-kiracı yeniden kayıt ErrTenantMismatch olmalı: %v", err)
	}
	if tn, _ := s.TenantForDevice(ctx, idA); tn != "acme" {
		t.Fatalf("cihaz kiracısı DEĞİŞMEMELİ: %q", tn)
	}
	row, _, _ := s.DeviceByID(ctx, idA)
	if string(row.HostnameEnc) != "host-A" {
		t.Fatalf("reddedilen kayıt cihaz alanlarını DEĞİŞTİRMEMELİ: %q", row.HostnameEnc)
	}

	// NEGATIF: PreferredDeviceID (token'a bağlı cihaz) yolu da aynı duvara tabi.
	_, err = s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
		PreferredDeviceID: idA, MACBlindIndex: []byte("mac-2"), TenantID: "globex",
	})
	if !errors.Is(err, enroll.ErrTenantMismatch) {
		t.Fatalf("PreferredDeviceID çapraz-kiracı reddedilmeli: %v", err)
	}
	if tn, _ := s.TenantForDevice(ctx, idA); tn != "acme" {
		t.Fatalf("cihaz kiracısı DEĞİŞMEMELİ (preferred yolu): %q", tn)
	}

	// NEGATIF: kiracılı cihaz, boş kiracılı (varsayılan) token ile de devralınamaz.
	_, err = s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{MACBlindIndex: []byte("mac-1"), TenantID: ""})
	if !errors.Is(err, enroll.ErrTenantMismatch) {
		t.Fatalf("boş kiracı token'ı kiracılı cihazı devralamaz: %v", err)
	}

	// POZITIF: aynı kiracıda yeniden kayıt aynı cihazı günceller.
	id2, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
		MACBlindIndex: []byte("mac-1"), HostnameEnc: []byte("host-A2"), TenantID: "acme",
	})
	if err != nil || id2 != idA {
		t.Fatalf("aynı kiracıda yeniden kayıt aynı cihaz olmalı: id=%q err=%v", id2, err)
	}
	row, _, _ = s.DeviceByID(ctx, idA)
	if string(row.HostnameEnc) != "host-A2" {
		t.Fatalf("meşru yeniden kayıt alanları güncellemeli: %q", row.HostnameEnc)
	}
	// POZITIF: PreferredDeviceID + aynı kiracı.
	if _, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
		PreferredDeviceID: idA, MACBlindIndex: []byte("mac-1"), TenantID: "acme",
	}); err != nil {
		t.Fatalf("aynı kiracıda preferred geçmeli: %v", err)
	}
}

// Z4b-02: yeniden kayıt, güvenlik durumunu (karantina) ACTIVE'e DÜŞÜRMEZ; yalnız
// henüz-aktif-olmayan durumlar ACTIVE olur.
func TestReEnrollKeepsSecurityStatus(t *testing.T) {
	ctx := context.Background()
	s := New()
	in := enroll.DeviceEnrollment{MACBlindIndex: []byte("mac-q"), TenantID: "acme"}
	id, err := s.UpsertEnrollingDevice(ctx, in)
	if err != nil {
		t.Fatal(err)
	}

	for _, keep := range []string{"QUARANTINED", "QUARANTINE_PENDING"} {
		_ = s.SetDeviceStatus(ctx, id, keep)
		if _, err := s.UpsertEnrollingDevice(ctx, in); err != nil {
			t.Fatal(err)
		}
		row, _, _ := s.DeviceByID(ctx, id)
		if row.Status != keep {
			t.Fatalf("yeniden kayıt %s durumunu KORUMALI, dönen: %q", keep, row.Status)
		}
	}
	// POZITIF: OFFLINE / UNINSTALLED cihaz yeniden kayıtla ACTIVE olur.
	for _, from := range []string{"OFFLINE", "UNINSTALLED", "PENDING_ENROLLMENT"} {
		_ = s.SetDeviceStatus(ctx, id, from)
		if _, err := s.UpsertEnrollingDevice(ctx, in); err != nil {
			t.Fatal(err)
		}
		row, _, _ := s.DeviceByID(ctx, id)
		if row.Status != "ACTIVE" {
			t.Fatalf("%s cihaz yeniden kayıtla ACTIVE olmalı, dönen: %q", from, row.Status)
		}
	}
}

// Token'ın mühürlü kiracısı sorgulanabilir (iptal yazma-yolunun kiracı kapısı).
func TestEnrollmentTokenTenantLookup(t *testing.T) {
	ctx := context.Background()
	s := New()
	if err := s.SaveEnrollmentToken(ctx, []byte("idx-1"), "", "acme", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.ListEnrollmentTokens(ctx, 10, "acme")
	if len(rows) != 1 {
		t.Fatalf("1 token beklenirdi: %d", len(rows))
	}
	tn, found, err := s.EnrollmentTokenTenant(ctx, rows[0].ID)
	if err != nil || !found || tn != "acme" {
		t.Fatalf("token kiracısı acme olmalı: %q found=%v err=%v", tn, found, err)
	}
	if _, found, _ := s.EnrollmentTokenTenant(ctx, "yok"); found {
		t.Fatal("var olmayan token found=false olmalı")
	}
}

// ListAdmins kiracı süzmesi: kiracılı çağıran yalnız kendi kiracısını (platform dahil değil) görür.
func TestListAdminsTenantFilter(t *testing.T) {
	ctx := context.Background()
	s := New()
	_, _ = s.CreateAdmin(ctx, "a@acme", "h", "ADMIN", "acme")
	_, _ = s.CreateAdmin(ctx, "g@globex", "h", "ADMIN", "globex")
	_, _ = s.CreateAdmin(ctx, "p@plat", "h", "ADMIN", "")
	acme, _ := s.ListAdmins(ctx, "acme")
	if len(acme) != 1 || acme[0].Email != "a@acme" {
		t.Fatalf("yalnız acme beklenirdi: %+v", acme)
	}
	all, _ := s.ListAdmins(ctx, "")
	if len(all) != 3 {
		t.Fatalf("boş süzme tümünü döner: %d", len(all))
	}
}

// S-2: kiracı öncesi (legacy) cihazların kiracısı boştur; örtük "default" token'ıyla
// yeniden kayıt PermissionDenied OLMAMALI (yükseltme gerilemesi) ve kiracı default'a
// normalleşmeli. Gerçek kiracılar için çapraz-kiracı taşıma yine engelli kalır.
func TestLegacyEmptyTenantDeviceReenrollsUnderDefault(t *testing.T) {
	ctx := context.Background()
	s := New()
	legacy, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
		MACBlindIndex: []byte("mac-legacy"), HostnameEnc: []byte("old"), TenantID: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tn, _ := s.TenantForDevice(ctx, legacy); tn != "" {
		t.Fatalf("legacy cihaz boş kiracıyla başlamalı: %q", tn)
	}

	// NEGATIF: gerçek bir kiracı, legacy (boş = default) cihazı devralamaz.
	for _, tn := range []string{"acme", "globex"} {
		if _, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
			MACBlindIndex: []byte("mac-legacy"), HostnameEnc: []byte("EVIL"), TenantID: tn,
		}); !errors.Is(err, enroll.ErrTenantMismatch) {
			t.Fatalf("%s token'ı legacy cihazı devralamaz: %v", tn, err)
		}
		if _, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
			PreferredDeviceID: legacy, MACBlindIndex: []byte("m2"), TenantID: tn,
		}); !errors.Is(err, enroll.ErrTenantMismatch) {
			t.Fatalf("%s token'ı preferred yolunda legacy cihazı devralamaz: %v", tn, err)
		}
	}
	if tn, _ := s.TenantForDevice(ctx, legacy); tn != "" {
		t.Fatalf("reddedilen kayıtlar kiracıyı değiştirmemeli: %q", tn)
	}

	// POZITIF: "default" token'ı aynı cihazı günceller ve kiracıyı default'a normalleştirir.
	id, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
		MACBlindIndex: []byte("mac-legacy"), HostnameEnc: []byte("new"), TenantID: "default",
	})
	if err != nil || id != legacy {
		t.Fatalf("default token'ı legacy cihazı yeniden kaydetmeli: id=%q err=%v", id, err)
	}
	if tn, _ := s.TenantForDevice(ctx, legacy); tn != "default" {
		t.Fatalf("kiracı default'a normalleşmeli: %q", tn)
	}
	row, _, _ := s.DeviceByID(ctx, legacy)
	if string(row.HostnameEnc) != "new" {
		t.Fatalf("alanlar güncellenmeli: %q", row.HostnameEnc)
	}
	// Normalleşmeden sonra artık gerçek kiracılar için de duvar aynı: acme yine reddedilir.
	if _, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
		MACBlindIndex: []byte("mac-legacy"), TenantID: "acme",
	}); !errors.Is(err, enroll.ErrTenantMismatch) {
		t.Fatalf("normalleşmiş cihaz acme'ye taşınamaz: %v", err)
	}

	// Preferred yolu: ikinci bir legacy cihaz da default token'ıyla geçer.
	l2, _ := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{MACBlindIndex: []byte("mac-l2"), TenantID: ""})
	if _, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
		PreferredDeviceID: l2, MACBlindIndex: []byte("mac-l2"), TenantID: "default",
	}); err != nil {
		t.Fatalf("preferred yolunda default token'ı legacy cihazı kaydetmeli: %v", err)
	}
	if tn, _ := s.TenantForDevice(ctx, l2); tn != "default" {
		t.Fatalf("preferred yolunda da normalleşmeli: %q", tn)
	}
}
