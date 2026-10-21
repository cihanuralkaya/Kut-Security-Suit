package memstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"kut.corp/suite/server/internal/enroll"
)

// Z4b-02 + S-3: bir kiracının token'ı, başka kiracıya ait cihazı (aynı MAC blind index)
// devralamaz; cihaz satırı değişmez. MAC tekilliği KİRACI BAŞINA olduğundan, başka kiracı
// aynı MAC ile KENDİ cihazını alır (MAC-squat DoS yok).
func TestEnrollCannotRehomeDeviceAcrossTenants(t *testing.T) {
	ctx := context.Background()
	s := New()
	idA, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
		MACBlindIndex: []byte("mac-1"), HostnameEnc: []byte("host-A"), TenantID: "acme",
	})
	if err != nil {
		t.Fatal(err)
	}

	// NEGATIF (re-home): globex aynı MAC ile enroll olur → acme'nin satırı DEĞİŞMEZ;
	// globex AYRI bir cihaz alır.
	idG, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
		MACBlindIndex: []byte("mac-1"), HostnameEnc: []byte("host-G"), TenantID: "globex",
	})
	if err != nil {
		t.Fatalf("aynı MAC başka kiracıda enroll olabilmeli (MAC-squat DoS yok): %v", err)
	}
	if idG == idA {
		t.Fatalf("globex acme'nin cihazını devralmamalı: %q", idG)
	}
	if tn, _ := s.TenantForDevice(ctx, idA); tn != "acme" {
		t.Fatalf("cihaz kiracısı DEĞİŞMEMELİ: %q", tn)
	}
	if tn, _ := s.TenantForDevice(ctx, idG); tn != "globex" {
		t.Fatalf("globex cihazı globex'e ait olmalı: %q", tn)
	}
	row, _, _ := s.DeviceByID(ctx, idA)
	if string(row.HostnameEnc) != "host-A" {
		t.Fatalf("diğer kiracının kaydı cihaz alanlarını DEĞİŞTİRMEMELİ: %q", row.HostnameEnc)
	}

	// NEGATIF: PreferredDeviceID (token'a bağlı cihaz) yolu hâlâ aynı duvara tabi.
	_, err = s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
		PreferredDeviceID: idA, MACBlindIndex: []byte("mac-2"), TenantID: "globex",
	})
	if !errors.Is(err, enroll.ErrTenantMismatch) {
		t.Fatalf("PreferredDeviceID çapraz-kiracı reddedilmeli: %v", err)
	}
	if tn, _ := s.TenantForDevice(ctx, idA); tn != "acme" {
		t.Fatalf("cihaz kiracısı DEĞİŞMEMELİ (preferred yolu): %q", tn)
	}

	// NEGATIF: boş kiracılı (= default) token acme'nin cihazını devralamaz; kendi satırını alır.
	idD, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{MACBlindIndex: []byte("mac-1"), TenantID: ""})
	if err != nil || idD == idA || idD == idG {
		t.Fatalf("boş kiracı token'ı kiracılı cihazı devralamaz, kendi satırını almalı: id=%q err=%v", idD, err)
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

// S-3: MAC-squat DoS. Kiracı A, B'nin cihazının MAC'ini ÖNCEDEN kaydetse bile B kendi
// cihazını enroll edebilir; A'nın satırı ve B'nin satırı birbirinden bağımsızdır.
func TestMACSquatCannotBlockOtherTenant(t *testing.T) {
	ctx := context.Background()
	s := New()
	mac := []byte("victim-mac")
	squat, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{MACBlindIndex: mac, HostnameEnc: []byte("squat"), TenantID: "evil"})
	if err != nil {
		t.Fatal(err)
	}
	victim, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{MACBlindIndex: mac, HostnameEnc: []byte("real"), TenantID: "victim"})
	if err != nil {
		t.Fatalf("kurban kiracı enroll olabilmeli: %v", err)
	}
	if victim == squat {
		t.Fatal("kurban, squat eden kiracının satırını almamalı")
	}
	if tn, _ := s.TenantForDevice(ctx, victim); tn != "victim" {
		t.Fatalf("kurban cihazı kurbana ait olmalı: %q", tn)
	}
	// Kurban yeniden kaydolunca KENDİ satırını günceller (squat'ınkini değil).
	again, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{MACBlindIndex: mac, HostnameEnc: []byte("real2"), TenantID: "victim"})
	if err != nil || again != victim {
		t.Fatalf("kurban yeniden kaydı kendi satırını güncellemeli: %q %v", again, err)
	}
	// Preferred yolunda başka bir cihazın (aynı kiracı) MAC'ine çakışma reddedilir.
	other, _ := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{MACBlindIndex: []byte("other"), TenantID: "victim"})
	if _, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{PreferredDeviceID: other, MACBlindIndex: mac, TenantID: "victim"}); err == nil {
		t.Fatal("aynı kiracıda çakışan MAC'e preferred ile geçiş reddedilmeli")
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

	// NEGATIF: gerçek bir kiracı, legacy (boş = default) cihazı devralamaz: MAC yolunda
	// (S-3) kendi AYRI satırını alır, legacy satır değişmez; preferred yolunda reddedilir.
	for _, tn := range []string{"acme", "globex"} {
		other, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
			MACBlindIndex: []byte("mac-legacy"), HostnameEnc: []byte("EVIL"), TenantID: tn,
		})
		if err != nil || other == legacy {
			t.Fatalf("%s token'ı legacy cihazı devralamaz, kendi satırını almalı: id=%q err=%v", tn, other, err)
		}
		if got, _ := s.TenantForDevice(ctx, other); got != tn {
			t.Fatalf("%s cihazı kendi kiracısında olmalı: %q", tn, got)
		}
		if _, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
			PreferredDeviceID: legacy, MACBlindIndex: []byte("m2"), TenantID: tn,
		}); !errors.Is(err, enroll.ErrTenantMismatch) {
			t.Fatalf("%s token'ı preferred yolunda legacy cihazı devralamaz: %v", tn, err)
		}
	}
	if tn, _ := s.TenantForDevice(ctx, legacy); tn != "" {
		t.Fatalf("diğer kayıtlar legacy kiracıyı değiştirmemeli: %q", tn)
	}
	if row, _, _ := s.DeviceByID(ctx, legacy); string(row.HostnameEnc) != "old" {
		t.Fatalf("legacy cihaz alanları değişmemeli: %q", row.HostnameEnc)
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
	// Normalleşmeden sonra da duvar aynı: acme preferred yoluyla yine taşıyamaz.
	if _, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
		PreferredDeviceID: legacy, MACBlindIndex: []byte("mac-legacy"), TenantID: "acme",
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
