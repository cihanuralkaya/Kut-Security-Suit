package cmdenvelope

import "sort"

// Cihaz komut tiplerinin kanonik adları. Bu adlar; kuyruk türü (DB `command_type`
// enum'u), proto `Command.CommandType` enum'u, imzalanan zarf alanı ve ajanın
// handleCommands anahtarı için TEK doğruluk kaynağıdır. Yeni bir tip önce buraya
// (özel bir satır olarak) eklenir; sürüklenme-koruma testleri (types_test.go ve
// ajan/sunucu testleri) proto, şema ve ajan anahtarı ile bu tablonun ayrışmasını
// derleme-sonrası (CI) yakalar.
const (
	TypeQuarantine         = "QUARANTINE"
	TypeUnquarantine       = "UNQUARANTINE"
	TypeLock               = "LOCK"
	TypeRestart            = "RESTART"
	TypeWipe               = "WIPE"
	TypeRunSignedScript    = "RUN_SIGNED_SCRIPT"
	TypeCollectFile        = "COLLECT_FILE"
	TypeCollectDiagnostics = "COLLECT_DIAGNOSTICS"
	TypeUninstall          = "UNINSTALL"
)

// Class, bir komut tipinin etki sınıfıdır. Sıfır değer (ClassInvalid) bilinçli olarak
// geçersizdir: sınıfı belirtilmemiş bir satır tablo testini kırar (fail-closed).
type Class uint8

const (
	ClassInvalid     Class = iota
	ClassDiagnostic        // salt okuma/tanı toplama; cihazı değiştirmez
	ClassContainment       // geri döndürülebilir izolasyon (QUARANTINE)
	ClassDisruption        // geri döndürülebilir kullanıcı kesintisi (LOCK, RESTART)
	ClassRelease           // kısıt kaldırma (UNQUARANTINE)
	ClassCollection        // cihazdan veri/dosya toplama (COLLECT_FILE)
	ClassScript            // imzalı betik yürütme (RUN_SIGNED_SCRIPT)
	ClassDestructive       // geri döndürülemez (WIPE, UNINSTALL)
)

// String, sınıfın okunur adını döner (log/audit/test çıktısı).
func (c Class) String() string {
	switch c {
	case ClassDiagnostic:
		return "diagnostic"
	case ClassContainment:
		return "containment"
	case ClassDisruption:
		return "disruption"
	case ClassRelease:
		return "release"
	case ClassCollection:
		return "collection"
	case ClassScript:
		return "script"
	case ClassDestructive:
		return "destructive"
	default:
		return "invalid"
	}
}

// Role, bir komutu başlatmak için gereken asgari yönetici rolüdür. Değerler
// admin.Role sabitleriyle BİREBİR aynıdır (admin.Role(spec.MinRole) dönüşümü); bu
// paket server/internal'a bağımlı olamayacağı için string olarak tutulur.
type Role string

const (
	RoleOperator Role = "OPERATOR"
	RoleAdmin    Role = "ADMIN"
)

// Spec, tek bir komut tipinin tam sınıflandırmasıdır. Değer kopyalanabilir (yalnız
// string/bool/sayısal alan), böylece çağıranlar tabloyu değiştiremez.
type Spec struct {
	// Name, kanonik tip adıdır (kuyruk/DB/imza alanı).
	Name string
	// ProtoEnum, proto Command.CommandType değer adıdır (ör. COMMAND_TYPE_WIPE).
	ProtoEnum string
	// Class, etki sınıfıdır; scope eşlemesi ve inceleme için.
	Class Class
	// Protected, ajan tarafında imzasız teslimin REDDEDİLMESİ gereken tiptir. false
	// yalnız ProtectedExemptReason dolu ise geçerlidir (tablo testi bunu zorlar).
	Protected bool
	// ProtectedExemptReason, Protected=false için ZORUNLU yazılı gerekçedir; Protected
	// satırlarında boş olmalıdır. Şu an hiçbir tip muaf değildir.
	ProtectedExemptReason string
	// MinRole, komutu başlatmak için gereken asgari yönetici rolüdür.
	MinRole Role
	// DualControl, tipin çift-kontrol (iki farklı ADMIN) kapsamında olduğunu bildirir.
	DualControl bool
	// Idempotent, aynı komutun yeniden yürütülmesinin güvenli olduğunu bildirir
	// (ajan yeniden-başlama sonrası STARTED kaydı için; bkz. W2 tasarımı 3.6).
	Idempotent bool
	// ScopeAction, scope.Action adıdır (küçük harf). ScopeExempt ise boştur. Bu paket
	// scope'a bağımlı olamaz; sunucu tarafı bu adı scope.Action'a çevirir.
	ScopeAction string
	// ScopeExempt, tipin scope/ROE DIŞLAMASINDAN muaf olduğunu bildirir (kısıt
	// kaldıran/zararsız tipler: dışlanmış cihazın karantinası kaldırılabilmeli).
	// RBAC ve kiracı denetimi muafiyetten ETKİLENMEZ.
	ScopeExempt bool
	// PlaneRouted, yönetici yolunda komut düzleminden (imza+authz) geçen tiptir.
	// false olanlar (COLLECT_DIAGNOSTICS: W2-S5'te taşınır; UNINSTALL: yönetici giriş
	// noktası yok) doğrudan depo yoluna gider ya da hiç gönderilmez.
	PlaneRouted bool
}

// specs, tablonun KAYNAĞIDIR (proto numarası sırasıyla). Değiştirmek bilinçli bir
// karardır: types_test.go ve ajan/sunucu testleri tutarlılığı doğrular.
var specs = []Spec{
	{
		Name: TypeQuarantine, ProtoEnum: "COMMAND_TYPE_QUARANTINE", Class: ClassContainment,
		Protected: true, MinRole: RoleOperator, Idempotent: true,
		ScopeAction: "quarantine", PlaneRouted: true,
	},
	{
		Name: TypeUnquarantine, ProtoEnum: "COMMAND_TYPE_UNQUARANTINE", Class: ClassRelease,
		Protected: true, MinRole: RoleOperator, Idempotent: true,
		ScopeExempt: true, PlaneRouted: true,
	},
	{
		Name: TypeRunSignedScript, ProtoEnum: "COMMAND_TYPE_RUN_SIGNED_SCRIPT", Class: ClassScript,
		Protected: true, MinRole: RoleAdmin,
		ScopeAction: "remote_command", PlaneRouted: true,
	},
	{
		Name: TypeUninstall, ProtoEnum: "COMMAND_TYPE_UNINSTALL", Class: ClassDestructive,
		Protected: true, MinRole: RoleAdmin, DualControl: true,
		ScopeAction: "wipe",
	},
	{
		Name: TypeCollectDiagnostics, ProtoEnum: "COMMAND_TYPE_COLLECT_DIAGNOSTICS", Class: ClassDiagnostic,
		Protected: true, MinRole: RoleOperator, Idempotent: true,
		ScopeExempt: true,
	},
	{
		Name: TypeCollectFile, ProtoEnum: "COMMAND_TYPE_COLLECT_FILE", Class: ClassCollection,
		Protected: true, MinRole: RoleOperator, Idempotent: true,
		ScopeAction: "remote_command", PlaneRouted: true,
	},
	{
		Name: TypeLock, ProtoEnum: "COMMAND_TYPE_LOCK", Class: ClassDisruption,
		Protected: true, MinRole: RoleOperator, Idempotent: true,
		ScopeAction: "lock", PlaneRouted: true,
	},
	{
		Name: TypeRestart, ProtoEnum: "COMMAND_TYPE_RESTART", Class: ClassDisruption,
		Protected: true, MinRole: RoleOperator,
		ScopeAction: "restart", PlaneRouted: true,
	},
	{
		Name: TypeWipe, ProtoEnum: "COMMAND_TYPE_WIPE", Class: ClassDestructive,
		Protected: true, MinRole: RoleAdmin, DualControl: true,
		ScopeAction: "wipe", PlaneRouted: true,
	},
}

var (
	byName  = indexBy(func(s Spec) string { return s.Name })
	byProto = indexBy(func(s Spec) string { return s.ProtoEnum })
)

func indexBy(key func(Spec) string) map[string]Spec {
	m := make(map[string]Spec, len(specs))
	for _, s := range specs {
		m[key(s)] = s
	}
	return m
}

// Lookup, kanonik ada göre (BÜYÜK harf, tam eşleşme) tip tanımını döner. Bilinmeyen
// ad → (Spec{}, false); çağıranlar bunu REDDETMELİDİR (fail-closed).
func Lookup(name string) (Spec, bool) {
	s, ok := byName[name]
	return s, ok
}

// LookupProto, proto enum değer adına (ör. "COMMAND_TYPE_WIPE") göre tip tanımını döner.
func LookupProto(protoEnum string) (Spec, bool) {
	s, ok := byProto[protoEnum]
	return s, ok
}

// Known, adın tabloda kayıtlı bir komut tipi olup olmadığını döner.
func Known(name string) bool {
	_, ok := byName[name]
	return ok
}

// Protected, ajanın bu tip için İMZASIZ teslimi reddetmesi gerekip gerekmediğini
// döner. Bilinmeyen/boş (UNSPECIFIED dâhil) ad TRUE döner: tanınmayan bir tip
// "korumasız" sayılamaz (fail-closed). Tabloda her tip korumalıdır — COLLECT_DIAGNOSTICS
// dâhil; muafiyet yalnız yazılı gerekçeyle (ProtectedExemptReason) tanımlanabilir.
func Protected(name string) bool {
	s, ok := byName[name]
	if !ok {
		return true
	}
	return s.Protected
}

// Idempotent, tipin yeniden yürütülmesinin güvenli olup olmadığını döner. Bilinmeyen
// tip false döner (fail-closed: yeniden yürütme varsayılmaz).
func Idempotent(name string) bool {
	s, ok := byName[name]
	return ok && s.Idempotent
}

// All, tüm tip tanımlarının (proto numarası sırasıyla) KOPYASINI döner.
func All() []Spec {
	out := make([]Spec, len(specs))
	copy(out, specs)
	return out
}

// Names, kanonik tip adlarını sıralı döner.
func Names() []string {
	out := make([]string, 0, len(specs))
	for _, s := range specs {
		out = append(out, s.Name)
	}
	sort.Strings(out)
	return out
}

// ProtectedNames, korumalı tiplerin adlarını sıralı döner (ajan/sunucu uyum testi).
func ProtectedNames() []string {
	out := make([]string, 0, len(specs))
	for _, s := range specs {
		if s.Protected {
			out = append(out, s.Name)
		}
	}
	sort.Strings(out)
	return out
}
