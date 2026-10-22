package memstore

import (
	"context"
	"errors"
	"testing"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/enroll"
)

// (memstore, db ile aynı): politika listesi kiracı süzülür (kendi + paylaşımlı), cihaz
// sayımı yalnız çağıranın kiracısını sayar, PolicyTenant sahibi döner, AssignPolicy kiracı
// bütünlüğünü zorlar, CurrentPolicy çapraz-kiracı atamayı ajana itmez.
func TestPolicyTenantScoping(t *testing.T) {
	ctx := context.Background()
	s := New()
	devA, _ := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{MACBlindIndex: []byte("pa"), TenantID: "acme"})
	devB, _ := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{MACBlindIndex: []byte("pb"), TenantID: "globex"})
	polA, _ := s.CreatePolicy(ctx, "acme-pol", "v1", "acme")
	polB, _ := s.CreatePolicy(ctx, "globex-pol", "v1", "globex")
	polS, _ := s.CreatePolicy(ctx, "shared-pol", "v1", "")

	if tn, ok, _ := s.PolicyTenant(ctx, polA); !ok || tn != "acme" {
		t.Fatalf("PolicyTenant acme olmalı: %q %v", tn, ok)
	}
	if tn, ok, _ := s.PolicyTenant(ctx, polS); !ok || tn != "" {
		t.Fatalf("paylaşımlı politika '' olmalı: %q %v", tn, ok)
	}
	if _, ok, _ := s.PolicyTenant(ctx, "yok"); ok {
		t.Fatal("bilinmeyen politika found=false olmalı")
	}

	// NEGATIF: kiracı bütünlüğü — acme cihazına globex politikası atanamaz (ErrForbidden), değişmez.
	if err := s.AssignPolicy(ctx, devA, polB); !errors.Is(err, admin.ErrForbidden) {
		t.Fatalf("çapraz-kiracı atama reddedilmeli: %v", err)
	}
	if err := s.AssignPolicy(ctx, "yok", polA); !errors.Is(err, admin.ErrForbidden) {
		t.Fatalf("bilinmeyen cihaz reddedilmeli: %v", err)
	}
	if _, pv, _ := s.AssignedPolicy(ctx, devA); pv != "" {
		t.Fatalf("reddedilen atama yazılmamalı: %q", pv)
	}
	// POZITIF: kendi + paylaşımlı.
	if err := s.AssignPolicy(ctx, devA, polA); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignPolicy(ctx, devB, polS); err != nil {
		t.Fatalf("paylaşımlı politika her kiracıya atanabilmeli: %v", err)
	}

	// Liste: acme yalnız kendi + paylaşımlı; globex politikası görünmez; sayım yalnız acme cihazları.
	rows, _ := s.ListPolicies(ctx, 0, "acme")
	names := map[string]int{}
	for _, r := range rows {
		names[r.Name] = r.DeviceCount
	}
	if _, leaked := names["globex-pol"]; leaked || len(names) != 2 {
		t.Fatalf("acme yalnız kendi + paylaşımlı politikaları görmeli: %v", names)
	}
	if names["acme-pol"] != 1 || names["shared-pol"] != 0 {
		t.Fatalf("cihaz sayımı yalnız acme cihazlarını saymalı (paylaşımlıda globex cihazı sızmaz): %v", names)
	}
	// POZITIF: platform (boş) hepsini görür, tüm cihazları sayar.
	all, _ := s.ListPolicies(ctx, 0, "")
	if len(all) != 3 {
		t.Fatalf("platform admini hepsini görmeli: %d", len(all))
	}
	for _, r := range all {
		if r.Name == "shared-pol" && r.DeviceCount != 1 {
			t.Fatalf("platform paylaşımlı sayımı 1 olmalı: %d", r.DeviceCount)
		}
		if r.Name == "globex-pol" && r.TenantID != "globex" {
			t.Fatalf("TenantID dönmeli: %q", r.TenantID)
		}
	}

	// CurrentPolicy: eski/bozuk çapraz-kiracı atama (doğrudan alan yazımı) ajana İTİLMEZ.
	s.mu.Lock()
	s.devices[devA].policyID = polB // bozuk durum simülasyonu
	s.mu.Unlock()
	if b, _ := s.CurrentPolicy(ctx, devA); b != nil {
		t.Fatal("çapraz-kiracı atanmış politika ajana verilmemeli")
	}
	s.mu.Lock()
	s.devices[devA].policyID = polA
	s.mu.Unlock()
	if b, _ := s.CurrentPolicy(ctx, devA); b == nil {
		t.Fatal("kendi kiracısının politikası verilmeli")
	}
}
