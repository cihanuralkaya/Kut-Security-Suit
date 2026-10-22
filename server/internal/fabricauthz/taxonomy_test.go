package fabricauthz

import (
	"context"
	"strings"
	"testing"

	"kut.corp/suite/cmdenvelope"
	"kut.corp/suite/server/internal/commandplane"
	"kut.corp/suite/server/internal/metrics"
	"kut.corp/suite/server/internal/scope"
)

// komut tablosu tabanlı sınıflandırma.

// taxonomyEngine: dev-in kapsamda, dev-ex hariç; WIPE yalnız wipeROE ise açık.
func taxonomyEngine(wipeROE bool) *scope.Engine {
	pol := &scope.Policy{
		Allowed:  scope.Selector{Devices: []string{"dev-in", "dev-ex"}},
		Excluded: scope.Selector{Devices: []string{"dev-ex"}},
	}
	if wipeROE {
		pol.Actions = map[scope.Action]bool{scope.ActionWipe: true}
	}
	return scope.New(pol)
}

func decide(t *testing.T, ca *CommandAuthorizer, action, dev string) commandplane.AuthorizationDecision {
	t.Helper()
	d, err := ca.Authorize(context.Background(), commandplane.ActionRequest{Subject: "op", Action: action, Object: dev})
	if err != nil {
		t.Fatalf("Authorize hata: %v", err)
	}
	return d
}

// N15: her tablo tipi için sınıflandırma var, scope aksiyonu scope paketinde KAYITLI ve sınıfa
// uygun etki seviyesinde; bilinmeyen tip her modda reddedilir.
func TestCommandAuthorizer_EveryTableTypeClassified(t *testing.T) {
	wantImpact := map[cmdenvelope.Class]scope.Impact{
		cmdenvelope.ClassContainment: scope.HighImpact,
		cmdenvelope.ClassDisruption:  scope.HighImpact,
		cmdenvelope.ClassCollection:  scope.Remote,
		cmdenvelope.ClassScript:      scope.Remote,
		cmdenvelope.ClassDestructive: scope.Destructive,
	}
	for _, s := range cmdenvelope.All() {
		if _, ok := commandplane.Spec(commandplane.CommandType(s.Name)); !ok {
			t.Errorf("%s düzlemde Spec'siz", s.Name)
		}
		if s.ScopeExempt {
			continue
		}
		if !scope.Known(scope.Action(s.ScopeAction)) {
			t.Errorf("%s: scope aksiyonu %q kayıtsız (ImpactOf Destructive'e düşerdi)", s.Name, s.ScopeAction)
			continue
		}
		if got, want := scope.ImpactOf(scope.Action(s.ScopeAction)), wantImpact[s.Class]; got != want {
			t.Errorf("%s (%s): etki %v, beklenen %v", s.Name, s.Class, got, want)
		}
	}
	for _, enforce := range []bool{true, false} {
		ca := NewCommandAuthorizerMode(taxonomyEngine(true), "t", enforce)
		for _, typ := range []string{"SELFDESTRUCT", "", "remote_command", "COMMAND_TYPE_UNSPECIFIED", "quarantined"} {
			if d := decide(t, ca, typ, "dev-in"); d.Allowed {
				t.Errorf("enforce=%v: bilinmeyen tip %q izinli (fail-closed ihlali)", enforce, typ)
			}
		}
	}
}

// N16: UNQUARANTINE enforce altında GERÇEK motorla izinli (hariç cihazda da), nil motorda da.
func TestCommandAuthorizer_UnquarantineAllowedUnderEnforce(t *testing.T) {
	ca := NewCommandAuthorizer(taxonomyEngine(false), "t")
	for _, dev := range []string{"dev-in", "dev-ex", "dev-unknown"} {
		if d := decide(t, ca, "UNQUARANTINE", dev); !d.Allowed {
			t.Errorf("UNQUARANTINE %s reddedildi: %s", dev, d.Reason)
		}
	}
	if d := decide(t, NewCommandAuthorizer(nil, "t"), "UNQUARANTINE", "dev-in"); !d.Allowed {
		t.Error("UNQUARANTINE motor yokken de guardScope ile aynı muaf kuralı izlemeli")
	}
	// QUARANTINE ise hariç cihazda reddedilir (muafiyet yalnız kısıt kaldırana).
	if d := decide(t, ca, "QUARANTINE", "dev-ex"); d.Allowed {
		t.Error("QUARANTINE hariç cihazda izinli olmamalı")
	}
	if d := decide(t, ca, "QUARANTINE", "dev-in"); !d.Allowed {
		t.Errorf("QUARANTINE kapsamda izinli olmalı: %s", d.Reason)
	}
}

// N17: COLLECT_FILE / RUN_SIGNED_SCRIPT kapsamdaki cihazda izinli, hariç cihazda red.
func TestCommandAuthorizer_CollectAndScriptFollowScope(t *testing.T) {
	ca := NewCommandAuthorizer(taxonomyEngine(false), "t")
	for _, typ := range []string{"COLLECT_FILE", "RUN_SIGNED_SCRIPT"} {
		if d := decide(t, ca, typ, "dev-in"); !d.Allowed {
			t.Errorf("%s kapsamda reddedildi: %s", typ, d.Reason)
		}
		if d := decide(t, ca, typ, "dev-ex"); d.Allowed {
			t.Errorf("%s hariç cihazda izinli olmamalı", typ)
		}
		if d := decide(t, ca, typ, "dev-out"); d.Allowed {
			t.Errorf("%s allow-scope dışında izinli olmamalı", typ)
		}
	}
	// Salt-okuma tanı toplama muaf.
	if d := decide(t, ca, "COLLECT_DIAGNOSTICS", "dev-ex"); !d.Allowed {
		t.Errorf("COLLECT_DIAGNOSTICS muaf olmalı: %s", d.Reason)
	}
}

// N18: yıkıcı tipler (WIPE, UNINSTALL) açık ROE olmadan reddedilir, ROE ile izinli.
func TestCommandAuthorizer_DestructiveNeedsROE(t *testing.T) {
	for _, typ := range []string{"WIPE", "UNINSTALL"} {
		if d := decide(t, NewCommandAuthorizer(taxonomyEngine(false), "t"), typ, "dev-in"); d.Allowed {
			t.Errorf("%s ROE açık değilken izinli olmamalı", typ)
		}
		if d := decide(t, NewCommandAuthorizer(taxonomyEngine(true), "t"), typ, "dev-in"); !d.Allowed {
			t.Errorf("%s ROE açıkken kapsamda izinli olmalı: %s", typ, d.Reason)
		}
		if d := decide(t, NewCommandAuthorizer(taxonomyEngine(true), "t"), typ, "dev-ex"); d.Allowed {
			t.Errorf("%s hariç cihazda izinli olmamalı", typ)
		}
	}
}

// N19: AUDIT modunda motor reddederse komut izinli döner + would-deny sayacı artar.
func TestCommandAuthorizer_AuditModeWouldDeny(t *testing.T) {
	ca := NewCommandAuthorizerMode(taxonomyEngine(false), "t", false)
	before := metrics.Counters()["cmd_would_deny"]
	d := decide(t, ca, "QUARANTINE", "dev-ex")
	if !d.Allowed || !strings.HasPrefix(d.Reason, "AUDIT would-deny") {
		t.Fatalf("audit modunda red izinli+AUDIT gerekçeli dönmeli: %+v", d)
	}
	if after := metrics.Counters()["cmd_would_deny"]; after != before+1 {
		t.Errorf("would-deny sayacı %d -> %d (artması beklenirdi)", before, after)
	}
	// İzinli karar sayacı artırmaz.
	if d := decide(t, ca, "QUARANTINE", "dev-in"); !d.Allowed || strings.Contains(d.Reason, "AUDIT") {
		t.Errorf("izinli karar AUDIT işaretlenmemeli: %+v", d)
	}
	if after := metrics.Counters()["cmd_would_deny"]; after != before+1 {
		t.Errorf("izinli karar sayacı artırdı: %d", after)
	}
	// ENFORCE modunda aynı karar gerçek red; sayaç değişmez.
	if d := decide(t, NewCommandAuthorizerMode(taxonomyEngine(false), "t", true), "QUARANTINE", "dev-ex"); d.Allowed {
		t.Error("enforce modunda red izin olmamalı")
	}
	if after := metrics.Counters()["cmd_would_deny"]; after != before+1 {
		t.Errorf("enforce reddi would-deny saymamalı: %d", after)
	}
}

// N20: nil motor — enforce: red, audit: izin; bilinmeyen tip her zaman red.
func TestCommandAuthorizer_NilEngineModes(t *testing.T) {
	if d := decide(t, NewCommandAuthorizerMode(nil, "t", true), "QUARANTINE", "dev-in"); d.Allowed {
		t.Error("nil motor + enforce: red beklenirdi")
	}
	if d := decide(t, NewCommandAuthorizerMode(nil, "t", false), "QUARANTINE", "dev-in"); !d.Allowed {
		t.Error("nil motor + audit: izin beklenirdi")
	}
	var nilCA *CommandAuthorizer
	if d := decide(t, nilCA, "WIPE", "dev-in"); d.Allowed {
		t.Error("nil yetkilendirici fail-closed reddetmeli")
	}
	if d := decide(t, NewCommandAuthorizerMode(nil, "t", false), "NOPE", "dev-in"); d.Allowed {
		t.Error("bilinmeyen tip audit+nil motorda bile red olmalı")
	}
}

// Yalnız kanonik (BÜYÜK harf, tam eşleşme) tip adı kabul edilir; küçük harf/boşluklu ad ve scope
// aksiyon adları ("remote_command") komut tipi sayılmaz (commandplane.Validate ile tutarlı).
func TestCommandAuthorizer_ExactRegisteredOnly(t *testing.T) {
	ca := NewCommandAuthorizer(taxonomyEngine(true), "t")
	if d := decide(t, ca, "WIPE", "dev-in"); !d.Allowed {
		t.Errorf("kanonik tip kabul edilmeli: %s", d.Reason)
	}
	if d := decide(t, ca, " wipe ", "dev-in"); d.Allowed {
		t.Error("küçük harf/boşluklu ad komut tipi sayılmamalı")
	}
	if d := decide(t, ca, "remote_command", "dev-in"); d.Allowed {
		t.Error("scope aksiyon adı komut tipi sayılmamalı")
	}
}

// komut adı HER yerde tam eşleşir. Kırpma/büyük harfe çevirme yok;
// Authorize ile commandplane.Validate aynı biçimleri reddeder.
func TestCommandName_ExactEverywhere(t *testing.T) {
	variants := func(name string) []string {
		return []string{
			strings.ToLower(name), " " + name, name + " ", "\t" + name, name + "\n", name + "\x00",
			strings.ToUpper(name[:1]) + strings.ToLower(name[1:]), strings.ReplaceAll(name, "_", "-"),
		}
	}
	for _, enforce := range []bool{true, false} {
		ca := NewCommandAuthorizerMode(taxonomyEngine(true), "t", enforce)
		for _, s := range cmdenvelope.All() {
			// Kanonik ad: motor çözer (bilinmeyen değil).
			if d := decide(t, ca, s.Name, "dev-in"); !d.Allowed && strings.Contains(d.Reason, "bilinmeyen komut tipi") {
				t.Errorf("enforce=%v: kanonik %s bilinmeyen sayıldı", enforce, s.Name)
			}
			for _, v := range variants(s.Name) {
				if v == s.Name {
					continue
				}
				d := decide(t, ca, v, "dev-in")
				if d.Allowed || !strings.Contains(d.Reason, "bilinmeyen komut tipi") {
					t.Errorf("enforce=%v: Authorize(%q) = %+v, bilinmeyen olarak reddedilmeliydi", enforce, v, d)
				}
				req := commandplane.CommandRequest{DeviceID: "dev-in", Type: commandplane.CommandType(v), IssuedBy: "admin:1"}
				if err := req.Validate(); err == nil {
					t.Errorf("Validate(%q) kabul etti; Authorize ile tutarsız", v)
				}
			}
			req := commandplane.CommandRequest{DeviceID: "dev-in", Type: commandplane.CommandType(s.Name), IssuedBy: "admin:1"}
			if err := req.Validate(); err != nil {
				t.Errorf("Validate(%q) kanonik adı reddetti: %v", s.Name, err)
			}
		}
	}
}
