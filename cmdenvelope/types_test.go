package cmdenvelope

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	kutv1 "kut.corp/suite/gen/kut/v1"
)

// validateSpecs, bir tip tablosunun yapısal değişmezlerini denetler. Gerçek tablo ve
// (kasıtlı bozuk) sentetik tablolar aynı denetleyiciden geçer; böylece korumanın
// kendisi de test edilir.
func validateSpecs(in []Spec) error {
	seen := map[string]bool{}
	seenProto := map[string]bool{}
	for _, s := range in {
		if s.Name == "" || s.Name != strings.ToUpper(s.Name) || strings.ContainsAny(s.Name, " \t\n") {
			return fmt.Errorf("ad geçersiz: %q", s.Name)
		}
		if seen[s.Name] {
			return fmt.Errorf("%s: yinelenen ad", s.Name)
		}
		seen[s.Name] = true
		if s.ProtoEnum != "COMMAND_TYPE_"+s.Name {
			return fmt.Errorf("%s: ProtoEnum %q beklenen COMMAND_TYPE_%s değil", s.Name, s.ProtoEnum, s.Name)
		}
		if seenProto[s.ProtoEnum] {
			return fmt.Errorf("%s: yinelenen proto adı", s.Name)
		}
		seenProto[s.ProtoEnum] = true
		if s.Class == ClassInvalid || s.Class.String() == "invalid" {
			return fmt.Errorf("%s: sınıf belirtilmemiş", s.Name)
		}
		if s.MinRole != RoleOperator && s.MinRole != RoleAdmin {
			return fmt.Errorf("%s: asgari rol geçersiz %q", s.Name, s.MinRole)
		}
		// Korumasız tip yalnız yazılı gerekçeyle; korumalı tipte gerekçe olmaz.
		if !s.Protected && len(strings.TrimSpace(s.ProtectedExemptReason)) < 20 {
			return fmt.Errorf("%s: korumasız ama yazılı gerekçe (>=20 karakter) yok", s.Name)
		}
		if s.Protected && s.ProtectedExemptReason != "" {
			return fmt.Errorf("%s: korumalı tipte muafiyet gerekçesi olamaz", s.Name)
		}
		// Scope: ya muaf ya da bir aksiyon adı; ikisi birden / hiçbiri geçersiz.
		if s.ScopeExempt == (s.ScopeAction != "") {
			return fmt.Errorf("%s: ScopeExempt ile ScopeAction tam biri olmalı", s.Name)
		}
		if s.ScopeAction != strings.ToLower(s.ScopeAction) {
			return fmt.Errorf("%s: ScopeAction küçük harf olmalı", s.Name)
		}
		// Yalnız kısıt kaldıran / salt-okuma sınıflar scope dışlamasından muaf olabilir.
		if s.ScopeExempt && s.Class != ClassRelease && s.Class != ClassDiagnostic {
			return fmt.Errorf("%s: %s sınıfı scope muafiyeti alamaz", s.Name, s.Class)
		}
		// Yıkıcı tipler: çift-kontrol, ADMIN, yeniden yürütme yok, muafiyet yok.
		if s.Class == ClassDestructive {
			if !s.DualControl || s.MinRole != RoleAdmin || s.Idempotent || s.ScopeExempt {
				return fmt.Errorf("%s: yıkıcı tip çift-kontrol+ADMIN+idempotent-değil+scope-kapılı olmalı", s.Name)
			}
		}
		if s.DualControl && s.Class != ClassDestructive {
			return fmt.Errorf("%s: çift-kontrol yalnız yıkıcı sınıfa aittir", s.Name)
		}
		// Betik/yıkıcı: asla operatör seviyesinde başlatılamaz.
		if (s.Class == ClassScript || s.Class == ClassDestructive) && s.MinRole != RoleAdmin {
			return fmt.Errorf("%s: %s sınıfı ADMIN gerektirir", s.Name, s.Class)
		}
	}
	return nil
}

func TestSpecTableInvariants(t *testing.T) {
	if err := validateSpecs(All()); err != nil {
		t.Fatalf("tip tablosu değişmezleri bozuk: %v", err)
	}
	if got := len(All()); got != 9 {
		t.Fatalf("tablo %d tip içeriyor; 9 bekleniyordu (yeni tip eklendiyse bu sayıyı ve tüm sürüklenme testlerini bilinçle güncelle)", got)
	}
}

// TestValidatorCatchesBadTables, korumanın kendisinin çalıştığını kanıtlar: kasıtlı bozuk
// tablolar reddedilmeli (özellikle gerekçesiz korumasız tip).
func TestValidatorCatchesBadTables(t *testing.T) {
	good := Spec{
		Name: "FOO", ProtoEnum: "COMMAND_TYPE_FOO", Class: ClassDiagnostic, Protected: true,
		MinRole: RoleOperator, ScopeExempt: true,
	}
	if err := validateSpecs([]Spec{good}); err != nil {
		t.Fatalf("geçerli sentetik satır reddedildi: %v", err)
	}
	mut := func(f func(*Spec)) Spec { s := good; f(&s); return s }
	bad := map[string]Spec{
		"unprotected-no-reason":    mut(func(s *Spec) { s.Protected = false }),
		"unprotected-short-reason": mut(func(s *Spec) { s.Protected = false; s.ProtectedExemptReason = "ok" }),
		"protected-with-reason":    mut(func(s *Spec) { s.ProtectedExemptReason = "gereksiz gerekçe yazısı burada" }),
		"no-class":                 mut(func(s *Spec) { s.Class = ClassInvalid }),
		"no-role":                  mut(func(s *Spec) { s.MinRole = "" }),
		"scope-both":               mut(func(s *Spec) { s.ScopeAction = "lock" }),
		"scope-none":               mut(func(s *Spec) { s.ScopeExempt = false }),
		"proto-mismatch":           mut(func(s *Spec) { s.ProtoEnum = "COMMAND_TYPE_BAR" }),
		"lowercase-name":           mut(func(s *Spec) { s.Name = "foo" }),
		"exempt-containment":       mut(func(s *Spec) { s.Class = ClassContainment }),
		"destructive-no-dual": mut(func(s *Spec) {
			s.Class = ClassDestructive
			s.ScopeExempt = false
			s.ScopeAction = "wipe"
			s.MinRole = RoleAdmin
		}),
		"script-operator": mut(func(s *Spec) { s.Class = ClassScript; s.ScopeExempt = false; s.ScopeAction = "remote_command" }),
	}
	for name, s := range bad {
		if err := validateSpecs([]Spec{s}); err == nil {
			t.Errorf("%s: bozuk satır kabul edildi", name)
		}
	}
	if err := validateSpecs([]Spec{good, good}); err == nil {
		t.Error("yinelenen ad kabul edildi")
	}
}

// TestProtectedCoversEveryKnownType (N124a): Protected() HER bilinen tip için true döner
// (COLLECT_DIAGNOSTICS muafiyeti kaldırıldı); bilinmeyen/boş/UNSPECIFIED de fail-closed true.
func TestProtectedCoversEveryKnownType(t *testing.T) {
	want := []string{
		"COLLECT_DIAGNOSTICS", "COLLECT_FILE", "LOCK", "QUARANTINE", "RESTART",
		"RUN_SIGNED_SCRIPT", "UNINSTALL", "UNQUARANTINE", "WIPE",
	}
	if got := ProtectedNames(); !reflect.DeepEqual(got, want) {
		t.Fatalf("korumalı küme beklenenden farklı:\n got  %v\n want %v", got, want)
	}
	for _, s := range All() {
		if !Protected(s.Name) {
			t.Errorf("%s korumasız: muafiyet yazılı gerekçe + bu testin bilinçli güncellenmesini gerektirir", s.Name)
		}
		if !s.Protected {
			t.Errorf("%s: tablo satırı Protected=false", s.Name)
		}
	}
	if !Protected(TypeCollectDiagnostics) {
		t.Error("COLLECT_DIAGNOSTICS korumalı olmalı (muafiyet blocker'ı)")
	}
	for _, name := range []string{"", "COMMAND_TYPE_UNSPECIFIED", "UNSPECIFIED", "quarantine", "Wipe", "NOPE", " WIPE"} {
		if Known(name) {
			t.Errorf("%q bilinen tip sayılmamalı (tam, büyük-harf eşleşme)", name)
		}
		if !Protected(name) {
			t.Errorf("%q bilinmeyen tip korumasız sayıldı (fail-closed ihlali)", name)
		}
		if Idempotent(name) {
			t.Errorf("%q bilinmeyen tip idempotent sayıldı", name)
		}
	}
}

func TestLookupAndCopyIsolation(t *testing.T) {
	for _, s := range All() {
		got, ok := Lookup(s.Name)
		if !ok || got != s {
			t.Errorf("Lookup(%s) tutarsız", s.Name)
		}
		p, ok := LookupProto(s.ProtoEnum)
		if !ok || p.Name != s.Name {
			t.Errorf("LookupProto(%s) tutarsız", s.ProtoEnum)
		}
	}
	if _, ok := Lookup("NOPE"); ok {
		t.Error("bilinmeyen tip bulundu")
	}
	// Dışarıdan değişiklik tabloyu etkilememeli.
	a := All()
	a[0].Protected = false
	a[0].Name = "HACKED"
	if !Protected(TypeQuarantine) || !Known(TypeQuarantine) || Known("HACKED") {
		t.Error("All() kopyası iç tabloyu değiştirebildi")
	}
	n := Names()
	n[0] = "HACKED"
	if Known("HACKED") {
		t.Error("Names() kopyası iç tabloyu değiştirdi")
	}
}

// TestDriftGuard_ProtoEnum (N20b): proto Command.CommandType enum'u ile tablo birebir aynı
// küme olmalı — iki yönde. UNSPECIFIED tabloda bulunmaz (reddedilir).
func TestDriftGuard_ProtoEnum(t *testing.T) {
	protoNames := map[string]int32{}
	for name, num := range kutv1.Command_CommandType_value {
		if num == int32(kutv1.Command_COMMAND_TYPE_UNSPECIFIED) {
			continue
		}
		protoNames[name] = num
	}
	for name := range protoNames {
		if _, ok := LookupProto(name); !ok {
			t.Errorf("proto enum %s tipi tabloda YOK (tabloya sınıf/rol/scope ile ekleyin)", name)
		}
	}
	for _, s := range All() {
		if _, ok := protoNames[s.ProtoEnum]; !ok {
			t.Errorf("tablo tipi %s proto enum'unda YOK (%s)", s.Name, s.ProtoEnum)
		}
	}
	if _, ok := LookupProto("COMMAND_TYPE_UNSPECIFIED"); ok {
		t.Error("UNSPECIFIED tabloda bulunmamalı")
	}
}

var (
	reSQLComment  = regexp.MustCompile(`(?m)--[^\n]*`)
	reQuotedList  = regexp.MustCompile(`\(\s*'[A-Z_]+'(?:\s*,\s*'[A-Z_]+')+\s*\)`)
	reQuotedItem  = regexp.MustCompile(`'([A-Z_]+)'`)
	reAlterAdd    = regexp.MustCompile(`(?is)ALTER\s+TYPE\s+command_type\s+ADD\s+VALUE\s+(?:IF\s+NOT\s+EXISTS\s+)?'([A-Z_]+)'`)
	reCreateEnum  = regexp.MustCompile(`(?is)CREATE\s+TYPE\s+command_type\s+AS\s+ENUM\s*\(([^)]*)\)`)
	reCommandLike = regexp.MustCompile(`'(?:QUARANTINE|UNQUARANTINE|COLLECT_FILE|RUN_SIGNED_SCRIPT|COLLECT_DIAGNOSTICS)'`)
)

// TestDriftGuard_DBSchema (N20b): db/*.sql içindeki `command_type` ENUM'u (CREATE + ALTER ... ADD
// VALUE) ve komut adlarından oluşan herhangi bir `IN (...)`/CHECK listesi tabloyla aynı kümede olmalı.
func TestDriftGuard_DBSchema(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "db", "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("db/*.sql bulunamadı: %v", err)
	}
	want := Names()
	foundEnum := false
	for _, f := range files {
		raw, err := os.ReadFile(f) // #nosec G304 -- depo içi sabit glob
		if err != nil {
			t.Fatal(err)
		}
		sql := reSQLComment.ReplaceAllString(string(raw), "")

		set := map[string]bool{}
		if m := reCreateEnum.FindStringSubmatch(sql); m != nil {
			foundEnum = true
			for _, it := range reQuotedItem.FindAllStringSubmatch(m[1], -1) {
				set[it[1]] = true
			}
			for _, a := range reAlterAdd.FindAllStringSubmatch(sql, -1) {
				set[a[1]] = true
			}
			if got := sortedKeys(set); !reflect.DeepEqual(got, want) {
				t.Errorf("%s: command_type ENUM tabloyla ayrıştı:\n db    %v\n table %v", f, got, want)
			}
		}
		// Enum dışında komut adı listesi taşıyan her CHECK/IN listesi de aynı küme olmalı.
		for _, lst := range reQuotedList.FindAllString(sql, -1) {
			if !reCommandLike.MatchString(lst) {
				continue
			}
			ls := map[string]bool{}
			for _, it := range reQuotedItem.FindAllStringSubmatch(lst, -1) {
				ls[it[1]] = true
			}
			if got := sortedKeys(ls); !reflect.DeepEqual(got, want) {
				t.Errorf("%s: komut-adı listesi tabloyla ayrıştı:\n list  %v\n table %v", f, got, want)
			}
		}
	}
	if !foundEnum {
		t.Fatal("db şemasında command_type ENUM'u bulunamadı (regex/şema değişti?)")
	}
}

// TestSchemaParserSelfCheck: ayrıştırıcı bir eksik tipi gerçekten yakalar.
func TestSchemaParserSelfCheck(t *testing.T) {
	sql := reSQLComment.ReplaceAllString("CREATE TYPE command_type AS ENUM ('QUARANTINE', 'WIPE'); -- 'LOCK'\n"+
		"ALTER TYPE command_type ADD VALUE IF NOT EXISTS 'LOCK';", "")
	m := reCreateEnum.FindStringSubmatch(sql)
	if m == nil {
		t.Fatal("CREATE TYPE ayrıştırılamadı")
	}
	set := map[string]bool{}
	for _, it := range reQuotedItem.FindAllStringSubmatch(m[1], -1) {
		set[it[1]] = true
	}
	for _, a := range reAlterAdd.FindAllStringSubmatch(sql, -1) {
		set[a[1]] = true
	}
	if got := sortedKeys(set); !reflect.DeepEqual(got, []string{"LOCK", "QUARANTINE", "WIPE"}) {
		t.Fatalf("ayrıştırıcı beklenmeyen küme verdi: %v", got)
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
