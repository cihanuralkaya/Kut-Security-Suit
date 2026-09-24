package memstore

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"kut.corp/suite/server/internal/enroll"
)

// UpsertEnrollingDevice: PreferredDeviceID boşsa MAC blind-index eşleşen mevcut
// cihazı yeniden kullanır (yeniden-kayıt); eşleşme yoksa yeni id atar.
func TestUpsertEnrollingDeviceReusesByMACBidx(t *testing.T) {
	ctx := context.Background()
	s := New()

	id1, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
		MACBlindIndex: []byte("mac-A"), OSPlatform: "windows", AgentVersion: "1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Aynı MAC bidx ile yeniden kayıt: aynı id dönmeli.
	id2, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
		MACBlindIndex: []byte("mac-A"), OSPlatform: "windows",
	})
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("aynı MAC bidx aynı cihazı güncellemeliydi: %q != %q", id1, id2)
	}
	// Farklı MAC bidx: yeni cihaz.
	id3, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{MACBlindIndex: []byte("mac-B")})
	if err != nil {
		t.Fatal(err)
	}
	if id3 == id1 {
		t.Fatalf("farklı MAC bidx yeni cihaz üretmeliydi, tekrar döndü: %q", id3)
	}

	// PreferredDeviceID verildiğinde aynen kullanılır.
	idP, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{PreferredDeviceID: "dev-pref"})
	if err != nil {
		t.Fatal(err)
	}
	if idP != "dev-pref" {
		t.Fatalf("PreferredDeviceID kullanılmalıydı, dönen: %q", idP)
	}

	// Yeni cihaz ACTIVE olmalı.
	row, ok, err := s.DeviceByID(ctx, id1)
	if err != nil || !ok {
		t.Fatalf("DeviceByID başarısız: ok=%v err=%v", ok, err)
	}
	if row.Status != "ACTIVE" {
		t.Fatalf("yeni cihaz ACTIVE olmalıydı, dönen: %q", row.Status)
	}
	if row.OSPlatform != "windows" {
		t.Fatalf("OSPlatform yansımadı: %q", row.OSPlatform)
	}
}

// DeviceByID: bilinmeyen cihaz için (zero, false, nil) döner.
func TestDeviceByIDUnknown(t *testing.T) {
	s := New()
	row, ok, err := s.DeviceByID(context.Background(), "yok")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatalf("bilinmeyen cihaz ok=false dönmeliydi")
	}
	if row.ID != "" {
		t.Fatalf("bilinmeyen cihaz boş satır dönmeliydi: %+v", row)
	}
}

// SetDeviceTags: etiketleri kopyalar; bilinmeyen cihaz no-op; DeviceByID sağlam
// bir kopya döner (dış slice değişimi içeriyi bozmaz).
func TestSetDeviceTags(t *testing.T) {
	ctx := context.Background()
	s := New()
	id := enrollDevice(t, s)

	tags := []string{"prod", "critical"}
	if err := s.SetDeviceTags(ctx, id, tags); err != nil {
		t.Fatal(err)
	}
	// Kaynağı değiştir: depodaki kopya etkilenmemeli.
	tags[0] = "MUTATED"

	row, _, _ := s.DeviceByID(ctx, id)
	if len(row.Tags) != 2 || row.Tags[0] != "prod" || row.Tags[1] != "critical" {
		t.Fatalf("etiketler kopyalanmalıydı: %+v", row.Tags)
	}

	// Bilinmeyen cihaz: no-op, hata yok.
	if err := s.SetDeviceTags(ctx, "yok", []string{"x"}); err != nil {
		t.Fatalf("bilinmeyen cihazda hata olmamalıydı: %v", err)
	}
}

// SaveCertificate + DeviceHasActiveCert + CertsByDevice + RevokeDeviceCerts +
// RevokedFingerprints: sertifika yaşam-döngüsü.
func TestCertificateLifecycle(t *testing.T) {
	ctx := context.Background()
	s := New()
	id := enrollDevice(t, s)

	// Başta aktif sertifika yok.
	if ok, _ := s.DeviceHasActiveCert(ctx, id); ok {
		t.Fatal("başlangıçta aktif sertifika olmamalıydı")
	}

	fp := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	nb := time.Now()
	na := nb.Add(24 * time.Hour)
	if err := s.SaveCertificate(ctx, enroll.CertRecord{
		DeviceID: id, Serial: "1001", Fingerprint: fp, NotBefore: nb, NotAfter: na,
	}); err != nil {
		t.Fatal(err)
	}

	if ok, _ := s.DeviceHasActiveCert(ctx, id); !ok {
		t.Fatal("kayıttan sonra aktif sertifika olmalıydı")
	}

	certs, err := s.CertsByDevice(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("1 sertifika beklenirdi, dönen: %d", len(certs))
	}
	if certs[0].Serial != "1001" {
		t.Fatalf("serial hatalı: %q", certs[0].Serial)
	}
	if certs[0].Fingerprint != hex.EncodeToString(fp) {
		t.Fatalf("fingerprint hex kodlanmalıydı: %q", certs[0].Fingerprint)
	}
	if certs[0].Revoked {
		t.Fatal("yeni sertifika iptal edilmemiş olmalı")
	}

	// İptal edilmemişken revoked-fingerprint yok.
	if rf, _ := s.RevokedFingerprints(ctx); len(rf) != 0 {
		t.Fatalf("iptal öncesi 0 revoked fp beklenirdi: %d", len(rf))
	}

	// İptal et.
	if err := s.RevokeDeviceCerts(ctx, id, "compromise"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.DeviceHasActiveCert(ctx, id); ok {
		t.Fatal("iptalden sonra aktif sertifika olmamalıydı")
	}
	certs, _ = s.CertsByDevice(ctx, id)
	if len(certs) != 1 || !certs[0].Revoked {
		t.Fatalf("sertifika iptal (revoked) işaretlenmeliydi: %+v", certs)
	}

	rf, _ := s.RevokedFingerprints(ctx)
	if len(rf) != 1 {
		t.Fatalf("1 revoked fingerprint beklenirdi: %d", len(rf))
	}
	if hex.EncodeToString(rf[0]) != hex.EncodeToString(fp) {
		t.Fatalf("revoked fingerprint eşleşmedi")
	}

	// Bilinmeyen cihaz sertifika listesi boş.
	if other, _ := s.CertsByDevice(ctx, "yok"); len(other) != 0 {
		t.Fatalf("bilinmeyen cihazda sertifika olmamalıydı: %d", len(other))
	}
}
