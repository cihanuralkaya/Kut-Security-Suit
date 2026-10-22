package admin

import (
	"context"
	"errors"
	"sort"
	"testing"
)

// policyFix: wallFixture + her kiracıda bir politika, bir paylaşımlı politika ve cihazlar.
type policyFix struct {
	svc                          *Service
	store                        *memStore
	pub                          *fakePublisher
	polAcme, polGlobex, polShare string
}

func newPolicyFix(t *testing.T) *policyFix {
	t.Helper()
	svc, store := wallFixture(t)
	seedTenantMaps(store)
	f := &policyFix{svc: svc, store: store, pub: &fakePublisher{}}
	svc.SetPublisher(f.pub)
	ctx := context.Background()
	f.polAcme, _ = store.CreatePolicy(ctx, "acme-pol", "v1", "acme")
	f.polGlobex, _ = store.CreatePolicy(ctx, "globex-pol", "v1", "globex")
	f.polShare, _ = store.CreatePolicy(ctx, "shared-pol", "v1", "")
	store.deviceTenant["d-acme"] = "acme"
	store.deviceTenant["d-globex"] = "globex"
	return f
}

var blockRule = RuleInput{Type: "APP_BLOCK_ALWAYS", Target: "evil.exe"}

// kiracıya bağlı admin başka kiracının ve paylaşımlı politikaya kural İTEMEZ; kendi
// politikasına ekleyebilir ve push yalnız o kiracının cihazlarına gider.
func TestPolicyAddRuleTenantWall(t *testing.T) {
	ctx := context.Background()
	f := newPolicyFix(t)
	s := f.store
	verGlobex, verShare := s.versions[f.polGlobex], s.versions[f.polShare]
	// Cihaz atamaları: globex politikası globex cihazında.
	s.assigned["d-globex"] = f.polGlobex

	// NEGATIF: acme ADMIN'i globex politikasına kural ekleyemez.
	if err := f.svc.AddPolicyRule(ctx, "acme-adm", f.polGlobex, blockRule); !errors.Is(err, ErrForbidden) {
		t.Fatalf("çapraz-kiracı kural ekleme reddedilmeli: %v", err)
	}
	if len(s.rules[f.polGlobex]) != 0 || s.versions[f.polGlobex] != verGlobex {
		t.Fatal("reddedilen çağrı kural eklememeli ve sürümü yükseltmemeli")
	}
	// NEGATIF: acme ADMIN'i paylaşımlı (platform) politikayı değiştiremez.
	if err := f.svc.AddPolicyRule(ctx, "acme-adm", f.polShare, blockRule); !errors.Is(err, ErrForbidden) {
		t.Fatalf("paylaşımlı politika kiracıya bağlı admin için salt-okunur: %v", err)
	}
	if len(s.rules[f.polShare]) != 0 || s.versions[f.polShare] != verShare {
		t.Fatal("paylaşımlı politika değişmemeli")
	}
	// NEGATIF: bilinmeyen politika fail-closed.
	if err := f.svc.AddPolicyRule(ctx, "acme-adm", "yok", blockRule); !errors.Is(err, ErrForbidden) {
		t.Fatalf("bilinmeyen politika reddedilmeli: %v", err)
	}
	if len(f.pub.published) != 0 {
		t.Fatalf("reddedilen çağrılar hiçbir cihaza push etmemeli: %v", f.pub.published)
	}

	// POZITIF: acme kendi politikasına ekler; push yalnız acme cihazına (eski/bozuk çapraz-kiracı
	// atama olan globex cihazı ATLANIR).
	s.assigned["d-acme"] = f.polAcme
	s.assigned["d-globex-bad"] = f.polAcme
	s.deviceTenant["d-globex-bad"] = "globex"
	if err := f.svc.AddPolicyRule(ctx, "acme-adm", f.polAcme, blockRule); err != nil {
		t.Fatalf("kendi politikasına kural eklemeli: %v", err)
	}
	if len(s.rules[f.polAcme]) != 1 {
		t.Fatal("kural eklenmeli")
	}
	got := append([]string(nil), f.pub.published...)
	sort.Strings(got)
	if len(got) != 1 || got[0] != "d-acme" {
		t.Fatalf("push yalnız politikanın kiracısındaki cihaza gitmeli: %v", got)
	}

	// POZITIF: platform admini kısıtsız (globex politikası + paylaşımlı).
	f.pub.published = nil
	if err := f.svc.AddPolicyRule(ctx, "plat", f.polGlobex, blockRule); err != nil {
		t.Fatalf("platform admini herhangi bir politikaya ekleyebilmeli: %v", err)
	}
	if err := f.svc.AddPolicyRule(ctx, "plat", f.polShare, blockRule); err != nil {
		t.Fatalf("platform admini paylaşımlı politikaya ekleyebilmeli: %v", err)
	}
	if len(f.pub.published) != 1 || f.pub.published[0] != "d-globex" {
		t.Fatalf("globex politikası globex cihazına push etmeli: %v", f.pub.published)
	}
}

// politika atama — kiracı bütünlüğü. Başka kiracının politikası atanamaz; paylaşımlı
// ve kendi politikası atanır; platform admini bile kiracılar arası atayamaz.
func TestPolicyAssignTenantWall(t *testing.T) {
	ctx := context.Background()
	f := newPolicyFix(t)
	s := f.store

	// NEGATIF: acme ADMIN'i globex politikasını kendi cihazına atayamaz.
	if err := f.svc.AssignPolicy(ctx, "acme-adm", "d-acme", f.polGlobex); !errors.Is(err, ErrForbidden) {
		t.Fatalf("başka kiracının politikası atanamaz: %v", err)
	}
	// NEGATIF: bilinmeyen politika.
	if err := f.svc.AssignPolicy(ctx, "acme-adm", "d-acme", "yok"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("bilinmeyen politika atanamaz: %v", err)
	}
	// NEGATIF: cihaz başka kiracının (mevcut cihaz kapısı).
	if err := f.svc.AssignPolicy(ctx, "acme-adm", "d-globex", f.polAcme); !errors.Is(err, ErrForbidden) {
		t.Fatalf("başka kiracının cihazına atanamaz: %v", err)
	}
	// NEGATIF (bütünlük değişmezi): platform admini de acme politikasını globex cihazına atayamaz.
	if err := f.svc.AssignPolicy(ctx, "plat", "d-globex", f.polAcme); !errors.Is(err, ErrForbidden) {
		t.Fatalf("platform admini bile kiracılar arası politika atayamaz: %v", err)
	}
	if len(s.assigned) != 0 {
		t.Fatalf("reddedilen atamalar yazılmamalı: %v", s.assigned)
	}

	// POZITIF: kendi politikası, paylaşımlı politika, platform + eşleşen kiracı.
	if err := f.svc.AssignPolicy(ctx, "acme-adm", "d-acme", f.polAcme); err != nil {
		t.Fatalf("kendi politikası atanmalı: %v", err)
	}
	if err := f.svc.AssignPolicy(ctx, "acme-adm", "d-acme", f.polShare); err != nil {
		t.Fatalf("paylaşımlı politika atanabilmeli: %v", err)
	}
	if err := f.svc.AssignPolicy(ctx, "plat", "d-globex", f.polGlobex); err != nil {
		t.Fatalf("platform admini eşleşen kiracıya atayabilmeli: %v", err)
	}
	if s.assigned["d-globex"] != f.polGlobex {
		t.Fatalf("atama yazılmalı: %v", s.assigned)
	}
}

// kural listeleme — başka kiracının politikası okunamaz; kendi + paylaşımlı okunur.
func TestPolicyListRulesTenantWall(t *testing.T) {
	ctx := context.Background()
	f := newPolicyFix(t)
	_ = f.store.AddPolicyRule(ctx, f.polGlobex, blockRule)
	_ = f.store.AddPolicyRule(ctx, f.polShare, blockRule)

	if _, err := f.svc.ListPolicyRules(ctx, "acme-op", f.polGlobex); !errors.Is(err, ErrForbidden) {
		t.Fatalf("başka kiracının kuralları okunamaz: %v", err)
	}
	if _, err := f.svc.ListPolicyRules(ctx, "acme-op", "yok"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("bilinmeyen politika reddedilmeli: %v", err)
	}
	if rules, err := f.svc.ListPolicyRules(ctx, "acme-op", f.polShare); err != nil || len(rules) != 1 {
		t.Fatalf("paylaşımlı politika okunabilmeli: %v %v", rules, err)
	}
	if _, err := f.svc.ListPolicyRules(ctx, "acme-op", f.polAcme); err != nil {
		t.Fatalf("kendi politikası okunabilmeli: %v", err)
	}
	if rules, err := f.svc.ListPolicyRules(ctx, "plat", f.polGlobex); err != nil || len(rules) != 1 {
		t.Fatalf("platform admini hepsini okuyabilmeli: %v %v", rules, err)
	}
}

// politika oluşturma — sahip kiracı sunucu-tarafı belirlenir.
func TestPolicyCreateTenantOwnership(t *testing.T) {
	ctx := context.Background()
	f := newPolicyFix(t)

	// Kiracıya bağlı admin: boş istek = kendi kiracısı; kendi adı da olur; başkası 403.
	id, err := f.svc.CreatePolicy(ctx, "acme-adm", "p1", "v1", "")
	if err != nil || f.store.polTenants[id] != "acme" {
		t.Fatalf("kiracılı admin kendi kiracısına oluşturmalı: %q %q %v", id, f.store.polTenants[id], err)
	}
	if id, err = f.svc.CreatePolicy(ctx, "acme-adm", "p2", "v1", "acme"); err != nil || f.store.polTenants[id] != "acme" {
		t.Fatalf("kendi kiracısını açıkça vermek geçmeli: %v", err)
	}
	n := len(f.store.policies)
	if _, err := f.svc.CreatePolicy(ctx, "acme-adm", "p3", "v1", "globex"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("başka kiracı adına politika oluşturulamaz: %v", err)
	}
	if len(f.store.policies) != n {
		t.Fatal("reddedilen oluşturma politika yazmamalı")
	}

	// Platform admini: boş = paylaşımlı; dolu = normalleştirilmiş kiracı; geçersiz = 400.
	if id, err = f.svc.CreatePolicy(ctx, "plat", "shared", "v1", ""); err != nil || f.store.polTenants[id] != "" {
		t.Fatalf("platform boş kiracı = paylaşımlı: %q %v", f.store.polTenants[id], err)
	}
	if id, err = f.svc.CreatePolicy(ctx, "plat", "g", "v1", "  GLOBEX "); err != nil || f.store.polTenants[id] != "globex" {
		t.Fatalf("platform kiracısı normalleşmeli: %q %v", f.store.polTenants[id], err)
	}
	if _, err := f.svc.CreatePolicy(ctx, "plat", "bad", "v1", "Bad Tenant!"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("geçersiz kiracı kimliği reddedilmeli: %v", err)
	}
}
