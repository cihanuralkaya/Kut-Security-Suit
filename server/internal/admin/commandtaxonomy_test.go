package admin

import (
	"context"
	"errors"
	"testing"

	"kut.corp/suite/cmdenvelope"
	"kut.corp/suite/server/internal/commandplane"
	"kut.corp/suite/server/internal/fabricauthz"
	"kut.corp/suite/server/internal/scope"
)

// enforceFixture, KUT_SCOPE_ENFORCE=1 üretim kablolamasını (scope motoru + GERÇEK
// fabricauthz yetkilendiricisi + imzalayan komut düzlemi) yerelde kurar. dev-in kapsamda,
// dev-ex hariç-tutulmuştur; WIPE yalnız wipeROE=true ise açıkça etkinleştirilir.
func enforceFixture(t *testing.T, wipeROE bool) (*Service, *memStore, *commandplane.Plane) {
	t.Helper()
	store := newMemStore()
	store.roles["op1"] = RoleOperator
	store.roles["viewer"] = RoleViewer
	store.roles["adminA"] = RoleAdmin
	store.roles["adminB"] = RoleAdmin
	svc, _ := newService(t, store)

	pol := &scope.Policy{
		Allowed:  scope.Selector{Devices: []string{"dev-in", "dev-ex"}},
		Excluded: scope.Selector{Devices: []string{"dev-ex"}},
	}
	if wipeROE {
		pol.Actions = map[scope.Action]bool{scope.ActionWipe: true}
	}
	eng := scope.New(pol)
	svc.SetScopeEngine(eng, true, "default")
	plane := newTestPlane(t, store, fabricauthz.NewCommandAuthorizer(eng, "default"))
	svc.SetCommandPlane(plane)
	return svc, store, plane
}

func queuedTypes(store *memStore) []string {
	var out []string
	for _, c := range store.commands {
		out = append(out, c.cmdType)
	}
	return out
}

// TestEnforce_QuarantineThenUnquarantine (N16): enforce altında yetkili rol karantinaya alıp
// SONRA kaldırabilir. Z2-02 öncesi UNQUARANTINE komut düzleminde ham ad olarak Destructive'e
// düşüp daima reddediliyordu (guardScope muaf tutarken düzlem tutmuyordu).
func TestEnforce_QuarantineThenUnquarantine(t *testing.T) {
	svc, store, _ := enforceFixture(t, false)
	ctx := context.Background()

	if err := svc.QuarantineDevice(ctx, "op1", "dev-in"); err != nil {
		t.Fatalf("QUARANTINE enforce altında geçmeli: %v", err)
	}
	if err := svc.ReleaseDevice(ctx, "op1", "dev-in"); err != nil {
		t.Fatalf("UNQUARANTINE enforce altında geçmeli (Z2-02): %v", err)
	}
	got := queuedTypes(store)
	if len(got) != 2 || got[0] != "QUARANTINE" || got[1] != "UNQUARANTINE" {
		t.Fatalf("beklenen [QUARANTINE UNQUARANTINE], alınan %v", got)
	}
}

// TestEnforce_UnquarantineRoleStillRBAC: scope muafiyeti RBAC'ı gevşetmez — VIEWER ne
// karantinaya alabilir ne de kaldırabilir; hiçbir şey kuyruğa girmez.
func TestEnforce_UnquarantineRoleStillRBAC(t *testing.T) {
	svc, store, _ := enforceFixture(t, false)
	ctx := context.Background()
	if err := svc.ReleaseDevice(ctx, "viewer", "dev-in"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("VIEWER UNQUARANTINE reddedilmeli: %v", err)
	}
	if err := svc.QuarantineDevice(ctx, "viewer", "dev-in"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("VIEWER QUARANTINE reddedilmeli: %v", err)
	}
	if len(store.commands) != 0 {
		t.Fatalf("reddedilen komutlar kuyruğa girmemeli: %v", queuedTypes(store))
	}
}

// TestEnforce_ExcludedDevice: hariç-tutulan cihaza QUARANTINE reddedilir ama kısıt kaldıran
// UNQUARANTINE hem guardScope hem düzlemde AYNI karara varır (muaf) — karantinadaki dışlanmış
// cihaz serbest bırakılabilir.
func TestEnforce_ExcludedDevice(t *testing.T) {
	svc, store, _ := enforceFixture(t, false)
	ctx := context.Background()
	if err := svc.QuarantineDevice(ctx, "op1", "dev-ex"); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("dışlanmış cihaza QUARANTINE ErrOutOfScope dönmeli: %v", err)
	}
	if err := svc.ReleaseDevice(ctx, "op1", "dev-ex"); err != nil {
		t.Fatalf("dışlanmış cihazda UNQUARANTINE (muaf) geçmeli: %v", err)
	}
	if err := svc.CollectDiagnostics(ctx, "op1", "dev-ex"); err != nil {
		t.Fatalf("COLLECT_DIAGNOSTICS (muaf) geçmeli: %v", err)
	}
	if got := queuedTypes(store); len(got) != 2 || got[0] != "UNQUARANTINE" || got[1] != "COLLECT_DIAGNOSTICS" {
		t.Fatalf("beklenen [UNQUARANTINE COLLECT_DIAGNOSTICS], alınan %v", got)
	}
}

// TestEnforce_CollectFileScope (N17): COLLECT_FILE kapsamdaki cihazda geçer (Z2-02: düzlemde
// bilinmeyen ad → Destructive → daima red), dışlanmış cihazda reddedilir.
func TestEnforce_CollectFileScope(t *testing.T) {
	svc, store, _ := enforceFixture(t, false)
	ctx := context.Background()
	if err := svc.CollectFile(ctx, "op1", "dev-in", "/var/evidence/a.txt"); err != nil {
		t.Fatalf("kapsamdaki cihazda COLLECT_FILE geçmeli: %v", err)
	}
	if err := svc.CollectFile(ctx, "op1", "dev-ex", "/var/evidence/a.txt"); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("dışlanmış cihazda COLLECT_FILE ErrOutOfScope dönmeli: %v", err)
	}
	if got := queuedTypes(store); len(got) != 1 || got[0] != "COLLECT_FILE" {
		t.Fatalf("yalnız kapsamdaki COLLECT_FILE kuyrukta olmalı: %v", got)
	}
}

// TestEnforce_PlaneSharesScopeDecision (N17): yönetici yolu olmayan RUN_SIGNED_SCRIPT dâhil,
// komut düzlemi kapsamdaki cihaza izin verir, dışlanmışa vermez (admin ile aynı tablo).
func TestEnforce_PlaneSharesScopeDecision(t *testing.T) {
	_, store, plane := enforceFixture(t, false)
	ctx := context.Background()
	if _, err := plane.Dispatch(ctx, commandplane.CommandRequest{DeviceID: "dev-in", Type: commandplane.TypeRunSignedScript, IssuedBy: "adminA"}); err != nil {
		t.Fatalf("kapsamdaki cihazda RUN_SIGNED_SCRIPT düzlemden geçmeli: %v", err)
	}
	if _, err := plane.Dispatch(ctx, commandplane.CommandRequest{DeviceID: "dev-ex", Type: commandplane.TypeRunSignedScript, IssuedBy: "adminA"}); err == nil {
		t.Fatal("dışlanmış cihazda RUN_SIGNED_SCRIPT reddedilmeli")
	}
	if got := queuedTypes(store); len(got) != 1 || got[0] != "RUN_SIGNED_SCRIPT" {
		t.Fatalf("yalnız kapsamdaki betik kuyrukta olmalı: %v", got)
	}
}

// TestEnforce_WipeKeepsROEAndDualControl (N18): WIPE açık ROE olmadan reddedilir; ROE ile geçer.
// Çift-kontrol (iki farklı ADMIN) enforce altında da korunur: kendi talebini onaylayamaz.
func TestEnforce_WipeKeepsROEAndDualControl(t *testing.T) {
	ctx := context.Background()

	svc, store, _ := enforceFixture(t, false)
	if err := svc.WipeDevice(ctx, "adminA", "dev-in"); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("ROE açık değilken WIPE reddedilmeli: %v", err)
	}
	if len(store.commands) != 0 {
		t.Fatalf("reddedilen WIPE kuyruğa girmemeli: %v", queuedTypes(store))
	}

	svc, store, _ = enforceFixture(t, true)
	svc.SetWipeDualControl(true)
	if err := svc.RequestWipe(ctx, "adminA", "dev-in", "kayıp"); err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveWipe(ctx, "adminA", "dev-in"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("kendi WIPE talebini onaylama reddedilmeli: %v", err)
	}
	if len(store.commands) != 0 {
		t.Fatalf("onaysız WIPE kuyruğa girmemeli: %v", queuedTypes(store))
	}
	if err := svc.ApproveWipe(ctx, "adminB", "dev-in"); err != nil {
		t.Fatalf("ikinci ADMIN onayı ROE açıkken geçmeli: %v", err)
	}
	if got := queuedTypes(store); len(got) != 1 || got[0] != "WIPE" {
		t.Fatalf("beklenen [WIPE], alınan %v", got)
	}
	// OPERATOR WIPE başlatamaz (tablo: ADMIN).
	if err := svc.WipeDevice(ctx, "op1", "dev-in"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("OPERATOR WIPE reddedilmeli: %v", err)
	}
}

// TestUnknownCommandTypeDenied (N15): kayıtsız tip hiçbir yoldan kuyruğa giremez — ne yönetici
// command() yolu (ErrInvalidInput), ne komut düzlemi (Validate), ne de yetkilendirici.
func TestUnknownCommandTypeDenied(t *testing.T) {
	svc, store, plane := enforceFixture(t, true)
	ctx := context.Background()
	permissive := fabricauthz.NewCommandAuthorizer(scope.New(&scope.Policy{
		Allowed: scope.Selector{Devices: []string{"dev-in"}},
		Actions: map[scope.Action]bool{scope.ActionWipe: true},
	}), "default")
	for _, typ := range []string{"SELFDESTRUCT", "", "quarantine", "COMMAND_TYPE_UNSPECIFIED"} {
		if err := svc.command(ctx, "adminA", "dev-in", typ, ""); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("command(%q) ErrInvalidInput dönmeli: %v", typ, err)
		}
		if _, err := plane.Dispatch(ctx, commandplane.CommandRequest{DeviceID: "dev-in", Type: commandplane.CommandType(typ), IssuedBy: "adminA"}); err == nil {
			t.Errorf("plane.Dispatch(%q) reddedilmeli", typ)
		}
	}
	for _, typ := range []string{"SELFDESTRUCT", "", "COMMAND_TYPE_UNSPECIFIED", "remote_command"} {
		d, _ := permissive.Authorize(ctx, commandplane.ActionRequest{Subject: "adminA", Action: typ, Object: "dev-in"})
		if d.Allowed {
			t.Errorf("yetkilendirici %q için izin verdi", typ)
		}
	}
	if len(store.commands) != 0 {
		t.Fatalf("bilinmeyen tipler kuyruğa girmemeli: %v", queuedTypes(store))
	}
	// Kayıtsız tip düzleme yönlenmez, doğrudan depoya da yazılmaz (command() önce reddeder).
	if planeRoutable("SELFDESTRUCT") || planeRoutable("") {
		t.Error("kayıtsız tip düzlem-yönlendirilebilir sayılmamalı")
	}
}

// TestServiceTablesAgree: yönetici tarafındaki türetilmiş kararlar (rol, scope, düzlem
// yönlendirme) paylaşılan tabloyla birebir örtüşür.
func TestServiceTablesAgree(t *testing.T) {
	wantRouted := map[string]bool{
		"QUARANTINE": true, "UNQUARANTINE": true, "LOCK": true, "RESTART": true,
		"WIPE": true, "RUN_SIGNED_SCRIPT": true, "COLLECT_FILE": true,
		"COLLECT_DIAGNOSTICS": false, "UNINSTALL": false,
	}
	for _, s := range cmdenvelope.All() {
		if got := planeRoutable(s.Name); got != wantRouted[s.Name] {
			t.Errorf("%s: planeRoutable=%v beklenen %v", s.Name, got, wantRouted[s.Name])
		}
		act, exempt, ok := commandScope(s.Name)
		if !ok || exempt != s.ScopeExempt || string(act) != s.ScopeAction {
			t.Errorf("%s: commandScope tabloyla çelişiyor (%q,%v,%v)", s.Name, act, exempt, ok)
		}
		if !exempt && !scope.Known(act) {
			t.Errorf("%s: scope aksiyonu %q scope paketinde kayıtlı değil", s.Name, act)
		}
		if Role(s.MinRole) != RoleOperator && Role(s.MinRole) != RoleAdmin {
			t.Errorf("%s: tablo rolü %q admin.Role değil", s.Name, s.MinRole)
		}
	}
	if _, _, ok := commandScope("NOPE"); ok {
		t.Error("kayıtsız tip için commandScope ok=true döndü")
	}
}

// TestCommandRolesFollowTable: her yönetici giriş noktası, tablodaki asgari rolü uygular.
func TestCommandRolesFollowTable(t *testing.T) {
	ctx := context.Background()
	type entry struct {
		typ  string
		call func(*Service, string) error
	}
	entries := []entry{
		{cmdenvelope.TypeQuarantine, func(s *Service, who string) error { return s.QuarantineDevice(ctx, who, "dev-in") }},
		{cmdenvelope.TypeUnquarantine, func(s *Service, who string) error { return s.ReleaseDevice(ctx, who, "dev-in") }},
		{cmdenvelope.TypeLock, func(s *Service, who string) error { return s.LockDevice(ctx, who, "dev-in") }},
		{cmdenvelope.TypeRestart, func(s *Service, who string) error { return s.RestartDevice(ctx, who, "dev-in") }},
		{cmdenvelope.TypeCollectDiagnostics, func(s *Service, who string) error { return s.CollectDiagnostics(ctx, who, "dev-in") }},
		{cmdenvelope.TypeCollectFile, func(s *Service, who string) error { return s.CollectFile(ctx, who, "dev-in", "/tmp/x") }},
		{cmdenvelope.TypeWipe, func(s *Service, who string) error { return s.WipeDevice(ctx, who, "dev-in") }},
	}
	for _, e := range entries {
		spec, ok := cmdenvelope.Lookup(e.typ)
		if !ok {
			t.Fatalf("%s tabloda yok", e.typ)
		}
		svc, _, _ := enforceFixture(t, true)
		if err := e.call(svc, "viewer"); !errors.Is(err, ErrForbidden) {
			t.Errorf("%s: VIEWER reddedilmeli: %v", e.typ, err)
		}
		opErr := e.call(svc, "op1")
		switch Role(spec.MinRole) {
		case RoleOperator:
			if opErr != nil {
				t.Errorf("%s: OPERATOR geçmeli: %v", e.typ, opErr)
			}
		case RoleAdmin:
			if !errors.Is(opErr, ErrForbidden) {
				t.Errorf("%s: OPERATOR reddedilmeli (tablo ADMIN): %v", e.typ, opErr)
			}
			if err := e.call(svc, "adminA"); err != nil {
				t.Errorf("%s: ADMIN geçmeli: %v", e.typ, err)
			}
		}
	}
}
