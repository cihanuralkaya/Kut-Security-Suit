package memstore

import (
	"context"
	"testing"

	kutv1 "kut.corp/suite/gen/kut/v1"
	"kut.corp/suite/server/internal/admin"
)

// SeedDemoPolicy: kural içeren demo politikası oluşturur; ListPolicyRules ile görülür.
func TestSeedDemoPolicy(t *testing.T) {
	ctx := context.Background()
	s := New()
	id, ver := s.SeedDemoPolicy()
	if id == "" || ver != "demo-1" {
		t.Fatalf("demo politika id/version hatalı: %q/%q", id, ver)
	}
	rules, _ := s.ListPolicyRules(ctx, id)
	if len(rules) != 1 || rules[0].Type != "APP_BLOCK_ALWAYS" {
		t.Fatalf("demo kural hatalı: %+v", rules)
	}
}

// CreatePolicy + AddPolicyRule + AssignPolicy + AssignedPolicy + DevicesForPolicy +
// CurrentPolicy: politika oluşturma, kural ekleme, cihaza atama akışı.
func TestPolicyLifecycle(t *testing.T) {
	ctx := context.Background()
	s := New()
	dev := enrollDevice(t, s)

	pid, err := s.CreatePolicy(ctx, "Kısıt", "v1")
	if err != nil {
		t.Fatal(err)
	}

	// ActiveDays boşsa depo varsayılanı (haftanın tüm günleri) uygulanır.
	if err := s.AddPolicyRule(ctx, pid, admin.RuleInput{Type: "APP_BLOCK_ALWAYS", Target: "bad.exe"}); err != nil {
		t.Fatal(err)
	}
	// Belirli günlerle ikinci kural.
	if err := s.AddPolicyRule(ctx, pid, admin.RuleInput{
		Type: "APP_TIME_BLOCK", Target: "game.exe", Start: "09:00", End: "17:00", ActiveDays: []int32{1, 2, 3},
	}); err != nil {
		t.Fatal(err)
	}
	// Bilinmeyen politikaya kural ekleme no-op.
	if err := s.AddPolicyRule(ctx, "yok", admin.RuleInput{Type: "NETWORK_RULE"}); err != nil {
		t.Fatal(err)
	}

	rules, _ := s.ListPolicyRules(ctx, pid)
	if len(rules) != 2 {
		t.Fatalf("2 kural beklenirdi: %d", len(rules))
	}
	// Varsayılan günler uygulanmış olmalı (7 gün).
	if len(rules[0].ActiveDays) != 7 {
		t.Fatalf("boş ActiveDays 7 güne genişlemeliydi: %+v", rules[0].ActiveDays)
	}
	if len(rules[1].ActiveDays) != 3 {
		t.Fatalf("belirtilen ActiveDays korunmalıydı: %+v", rules[1].ActiveDays)
	}

	// Atama.
	if err := s.AssignPolicy(ctx, dev, pid); err != nil {
		t.Fatal(err)
	}
	gotPID, gotVer, _ := s.AssignedPolicy(ctx, dev)
	if gotPID != pid || gotVer != "v1" {
		t.Fatalf("atanan politika hatalı: %q/%q", gotPID, gotVer)
	}

	devs, _ := s.DevicesForPolicy(ctx, pid)
	if len(devs) != 1 || devs[0] != dev {
		t.Fatalf("politikaya atanan cihaz hatalı: %+v", devs)
	}

	// CurrentPolicy proto paketini döner.
	bundle, err := s.CurrentPolicy(ctx, dev)
	if err != nil {
		t.Fatal(err)
	}
	if bundle == nil || bundle.PolicyVersion != "v1" {
		t.Fatalf("CurrentPolicy paketi hatalı: %+v", bundle)
	}
	if len(bundle.Rules) != 2 {
		t.Fatalf("paket 2 kural içermeliydi: %d", len(bundle.Rules))
	}

	// Atanmamış cihaz → nil paket.
	other := "dev-unassigned"
	if b, _ := s.CurrentPolicy(ctx, other); b != nil {
		t.Fatalf("atanmamış/bilinmeyen cihaz nil paket dönmeliydi: %+v", b)
	}
	// AssignedPolicy bilinmeyen cihaz.
	if p, v, _ := s.AssignedPolicy(ctx, "yok"); p != "" || v != "" {
		t.Fatalf("bilinmeyen cihaz boş atama dönmeliydi: %q/%q", p, v)
	}
	// ListPolicyRules bilinmeyen politika nil.
	if r, _ := s.ListPolicyRules(ctx, "yok"); r != nil {
		t.Fatalf("bilinmeyen politika nil kural dönmeliydi: %+v", r)
	}
}

// BumpPolicyVersion: politika sürümünü yükseltir ve atanmış cihazların
// policyVersion'ını günceller; bilinmeyen politika boş döner.
func TestBumpPolicyVersion(t *testing.T) {
	ctx := context.Background()
	s := New()
	dev := enrollDevice(t, s)
	pid, _ := s.CreatePolicy(ctx, "P", "v1")
	if err := s.AssignPolicy(ctx, dev, pid); err != nil {
		t.Fatal(err)
	}

	nv, err := s.BumpPolicyVersion(ctx, pid)
	if err != nil {
		t.Fatal(err)
	}
	if nv == "" || nv == "v1" {
		t.Fatalf("yeni sürüm üretilmeliydi: %q", nv)
	}
	// Atanmış cihazın sürümü de güncellenmiş olmalı.
	_, gotVer, _ := s.AssignedPolicy(ctx, dev)
	if gotVer != nv {
		t.Fatalf("cihaz sürümü bump'a uymalıydı: %q != %q", gotVer, nv)
	}

	// Bilinmeyen politika.
	if v, _ := s.BumpPolicyVersion(ctx, "yok"); v != "" {
		t.Fatalf("bilinmeyen politika boş sürüm dönmeliydi: %q", v)
	}
}

// ruleTypeToProto: bilinen tipler + bilinmeyen → UNSPECIFIED.
func TestRuleTypeToProto(t *testing.T) {
	cases := map[string]kutv1.PolicyRule_RuleType{
		"APP_TIME_BLOCK":   kutv1.PolicyRule_RULE_TYPE_APP_TIME_BLOCK,
		"APP_BLOCK_ALWAYS": kutv1.PolicyRule_RULE_TYPE_APP_BLOCK_ALWAYS,
		"NETWORK_RULE":     kutv1.PolicyRule_RULE_TYPE_NETWORK_RULE,
		"WAT":              kutv1.PolicyRule_RULE_TYPE_UNSPECIFIED,
		"":                 kutv1.PolicyRule_RULE_TYPE_UNSPECIFIED,
	}
	for in, want := range cases {
		if got := ruleTypeToProto(in); got != want {
			t.Errorf("ruleTypeToProto(%q)=%v, beklenen %v", in, got, want)
		}
	}
}

// SeedAdmin/CreateAdmin/SetAdminRole/DeactivateAdmin/ListAdmins/AdminRole akışı.
func TestAdminLifecycle(t *testing.T) {
	ctx := context.Background()
	s := New()

	id1 := s.SeedAdmin("zeta@x", "h1", admin.RoleViewer)
	id2, err := s.CreateAdmin(ctx, "alpha@x", "h2", admin.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}

	// AdminRole.
	if r, _ := s.AdminRole(ctx, id1); r != admin.RoleViewer {
		t.Fatalf("id1 rolü VIEWER olmalıydı: %v", r)
	}
	if r, _ := s.AdminRole(ctx, "yok"); r != admin.Role("") {
		t.Fatalf("bilinmeyen admin boş rol dönmeliydi: %v", r)
	}

	// SetAdminRole.
	if err := s.SetAdminRole(ctx, id1, admin.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.AdminRole(ctx, id1); r != admin.RoleAdmin {
		t.Fatalf("rol güncellenmeliydi: %v", r)
	}

	// ListAdmins e-postaya göre sıralı (alpha < zeta).
	list, _ := s.ListAdmins(ctx)
	if len(list) != 2 {
		t.Fatalf("2 admin beklenirdi: %d", len(list))
	}
	if list[0].Email != "alpha@x" || list[1].Email != "zeta@x" {
		t.Fatalf("ListAdmins e-postaya göre sıralı olmalıydı: %+v", list)
	}
	// Parola hash'i sızmamalı (AdminInfo'da alan yok — derleme garantisi).

	// DeactivateAdmin.
	if err := s.DeactivateAdmin(ctx, id2); err != nil {
		t.Fatal(err)
	}
	list, _ = s.ListAdmins(ctx)
	for _, a := range list {
		if a.ID == id2 && a.Active {
			t.Fatal("id2 pasifleştirilmeliydi")
		}
	}
}

// MFA akışı: SetPendingMFASecret → LookupMFA (enrolled=false) → ActivateMFA →
// LookupMFA (enrolled=true) → DisableMFA (temizlenir).
func TestMFALifecycle(t *testing.T) {
	ctx := context.Background()
	s := New()
	id := s.SeedAdmin("mfa@x", "h", admin.RoleAdmin)

	// Başta sır yok.
	if sec, on, _ := s.LookupMFA(ctx, id); sec != "" || on {
		t.Fatalf("başlangıçta MFA olmamalıydı: %q/%v", sec, on)
	}

	if err := s.SetPendingMFASecret(ctx, id, "SECRET123"); err != nil {
		t.Fatal(err)
	}
	sec, on, _ := s.LookupMFA(ctx, id)
	if sec != "SECRET123" || on {
		t.Fatalf("bekleyen sır ayarlanmalı ama etkin olmamalıydı: %q/%v", sec, on)
	}

	if err := s.ActivateMFA(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, on, _ := s.LookupMFA(ctx, id); !on {
		t.Fatal("ActivateMFA sonrası etkin olmalıydı")
	}

	if err := s.DisableMFA(ctx, id); err != nil {
		t.Fatal(err)
	}
	if sec, on, _ := s.LookupMFA(ctx, id); sec != "" || on {
		t.Fatalf("DisableMFA sır ve durumu temizlemeliydi: %q/%v", sec, on)
	}

	// Sır yokken ActivateMFA etkinleştirmemeli.
	id2 := s.SeedAdmin("nomfa@x", "h", admin.RoleViewer)
	if err := s.ActivateMFA(ctx, id2); err != nil {
		t.Fatal(err)
	}
	if _, on, _ := s.LookupMFA(ctx, id2); on {
		t.Fatal("sır yokken ActivateMFA etkinleştirmemeliydi")
	}

	// Bilinmeyen admin LookupMFA.
	if sec, on, _ := s.LookupMFA(ctx, "yok"); sec != "" || on {
		t.Fatalf("bilinmeyen admin boş MFA dönmeliydi: %q/%v", sec, on)
	}
}
