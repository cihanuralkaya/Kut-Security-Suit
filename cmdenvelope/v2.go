package cmdenvelope

// Komut zarfı v2 — W2 "Signed Command Fabric" tel formatı (S2'de DONDURULDU).
//
// v1 (CanonicalBytes) hiçbir zaman tele çıkmadı; v2 telde görülen İLK sürümdür. v1
// baytları bu dosyadan etkilenmez. Bu dosyadaki kodlama ve sınırlar ajan sürümlerine
// gömüldükten sonra değiştirilemez (her değişiklik bir ajan dağıtımı gerektirir).
//
// Bu paket yalnız standart kütüphaneyi kullanır: ajan bu paketi import eder.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Etki alanı etiketleri. Her imzalı nesne türü kendi etiketiyle başlar; bir türün
// imzası başka bir tür olarak sunulduğunda doğrulama başarısız olur.
const (
	DomainEnvelopeV2 = "kut-cmd-envelope-v2"
	DomainParamsV2   = "kut-cmd-params-v2"
	DomainTrustV2    = "kut-cmd-trust-v2"
)

// EnvelopeVersion2, Command.envelope_version değeridir. 0 = zarfsız (eski); 1 ve diğer
// her değer reddedilir.
const EnvelopeVersion2 = 2

// Sert sınırlar (sunucu doğrulaması ve VerifyV2 AYNI fonksiyonları kullanır).
const (
	KeyIDHexLen         = 32 // hex(sha256(pub)[:16]) = 128 bit
	CommandIDLen        = 36 // kanonik küçük harfli UUIDv4
	NonceHexLen         = 32 // 16 rastgele bayt, küçük harfli hex
	MaxDeviceIDLen      = 64 // X.509 CN üst sınırı
	MaxTenantIDLen      = 63
	MaxPrincipalLen     = 128 // requested_by / approved_by / correlation_id
	MaxTypeLen          = 32
	SignatureLen        = ed25519.SignatureSize
	MaxExtraSignatures  = 8
	MaxParamKeys        = 32
	MaxParamKeyLen      = 64
	MaxParamStringBytes = 256 << 10
	MaxParamsTotalBytes = 512 << 10
	MaxParamListItems   = 64
	MaxLifetime         = 31 * 24 * time.Hour
	ClockSkew           = 2 * time.Minute
)

// Params değer türü etiketleri (params_digest kodlamasında).
const (
	paramTagString byte = 0x01
	paramTagList   byte = 0x02
)

// Reason, bir reddin makine-okunur nedenidir. Ajan olayları ve metrik etiketleri bu
// adları aynen kullanır.
type Reason string

const (
	ReasonUnsupportedVersion Reason = "unsupported_version"
	ReasonMalformedEnvelope  Reason = "malformed_envelope"
	ReasonMalformedParams    Reason = "malformed_params"
	ReasonUnknownType        Reason = "unknown_type"
	ReasonBadLifetime        Reason = "bad_lifetime"
	ReasonUnknownKey         Reason = "unknown_key"
	ReasonKeyExpired         Reason = "key_expired"
	ReasonBadSignature       Reason = "bad_signature"
	ReasonBadDeviceID        Reason = "bad_device_id"
	ReasonClockUnsynced      Reason = "clock_unsynced"
	ReasonNotYetValid        Reason = "not_yet_valid"
	ReasonExpired            Reason = "expired"

	// Güven bildirimi (trust.go) nedenleri.
	ReasonMalformedStatement Reason = "malformed_statement"
	ReasonStaleEpoch         Reason = "stale_epoch"
	ReasonEpochSkipped       Reason = "epoch_skipped"
	ReasonThresholdNotMet    Reason = "threshold_not_met"
	ReasonSignerNotRoot      Reason = "signer_not_root"
	ReasonPinRequired        Reason = "pin_required"
	ReasonChainIncomplete    Reason = "chain_incomplete"
	ReasonKeyNotInChain      Reason = "key_not_in_chain"
)

// Transient, nedenin GEÇİCİ olduğunu (yeniden denenmeli; kalıcı ret olarak kaydedilmez,
// ack'lenmez) bildirir: bilinmeyen anahtar (bildirim henüz gelmedi), senkronsuz saat,
// henüz geçerli olmayan zarf.
func (r Reason) Transient() bool {
	switch r {
	case ReasonUnknownKey, ReasonClockUnsynced, ReasonNotYetValid:
		return true
	}
	return false
}

// Error, tipli bir doğrulama/biçim hatasıdır.
type Error struct {
	Reason Reason
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return "cmdenvelope: " + string(e.Reason)
	}
	return "cmdenvelope: " + string(e.Reason) + ": " + e.Detail
}

func newErr(r Reason, format string, a ...any) *Error {
	return &Error{Reason: r, Detail: fmt.Sprintf(format, a...)}
}

// ReasonOf, hatadaki Reason'u döner; *Error değilse "" döner.
func ReasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

// Param, tek bir komut parametresidir: dize YA DA dize listesi (başka tür yok).
type Param struct {
	Key    string
	Value  string   // IsList=false iken değer
	List   []string // IsList=true iken öğeler
	IsList bool
}

// StringParam, dize değerli parametre üretir.
func StringParam(key, value string) Param { return Param{Key: key, Value: value} }

// ListParam, dize-listesi değerli parametre üretir.
func ListParam(key string, items ...string) Param {
	return Param{Key: key, List: items, IsList: true}
}

// Signature, bir anahtarın zarf üzerindeki imzasıdır (extra_signatures öğesi).
type Signature struct {
	KeyID string
	Sig   []byte
}

// Envelope, telde taşınan v2 zarfıdır. device_id TELDE YOKTUR: imzalayan hedef cihaz
// kimliğini, doğrulayan KENDİ kimliğini ayrıca verir (CanonicalV2/VerifyV2).
type Envelope struct {
	Version       uint32 // telde envelope_version; yalnız 2 geçerli
	KeyID         string // birincil imza anahtarının kimliği
	CommandID     string
	TenantID      string
	Type          string // kanonik ad (types.go)
	RequestedBy   string
	ApprovedBy    string
	CorrelationID string
	Sequence      uint64
	Nonce         string
	IssuedAtNS    int64
	ExpiresAtNS   int64
	Params        []Param

	Signature       []byte      // birincil imza (KeyID anahtarı)
	ExtraSignatures []Signature // aynı iletiye kendi key_id'leriyle atılan imzalar
}

// Fields, İMZALANAN iletinin alanlarıdır (zarf + cihaz kimliği + params özeti).
type Fields struct {
	KeyID         string
	CommandID     string
	DeviceID      string
	TenantID      string
	Type          string
	RequestedBy   string
	ApprovedBy    string
	CorrelationID string
	Sequence      uint64
	Nonce         string
	IssuedAtNS    int64
	ExpiresAtNS   int64
	ParamsDigest  [32]byte
}

// KeyID, açık anahtarın 128-bit kimliğidir: hex(sha256(pub)[:16]). Geçersiz boyutta ""
// döner (doğrulamayı geçemez).
func KeyID(pub ed25519.PublicKey) string {
	if len(pub) != ed25519.PublicKeySize {
		return ""
	}
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// RequiredSignatures, tipin gerektirdiği asgari GEÇERLİ imza sayısıdır. W2'de her tip
// için 1; WIPE/UNINSTALL için ileride 2-of-N sınıfı bu kancadan açılır (wire değişmez).
func RequiredSignatures(cmdType string) int { return 1 }

// ---- kodlama yardımcıları -------------------------------------------------

func appendLP(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

func appendLPBytes(b, v []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
	return append(b, v...)
}

func appendU32(b []byte, n uint32) []byte { return binary.BigEndian.AppendUint32(b, n) }
func appendU64(b []byte, n uint64) []byte { return binary.BigEndian.AppendUint64(b, n) }
func appendI64(b []byte, n int64) []byte  { return binary.BigEndian.AppendUint64(b, uint64(n)) }

// reader, katı (tam-tüketen) bir ayrıştırıcıdır: her okuma sınır denetimlidir ve ilk
// hata sonraki tüm okumaları durdurur.
type reader struct {
	b   []byte
	err error
}

func (r *reader) fail(format string, a ...any) {
	if r.err == nil {
		r.err = fmt.Errorf(format, a...)
	}
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.fail("kısa girdi: %d bayt isteniyor, %d var", n, len(r.b))
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u32() uint32 {
	v := r.take(4)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v)
}

func (r *reader) u64() uint64 {
	v := r.take(8)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint64(v)
}

func (r *reader) i64() int64 { return int64(r.u64()) }

func (r *reader) byte1() byte {
	v := r.take(1)
	if v == nil {
		return 0
	}
	return v[0]
}

// lp, uzunluk-önekli bir alanı okur; uzunluk max'ı aşarsa VEYA kalan bayttan büyükse
// bellek ayrılmadan reddedilir.
func (r *reader) lp(max int) []byte {
	n := r.u32()
	if r.err != nil {
		return nil
	}
	if int64(n) > int64(max) {
		r.fail("alan uzunluğu %d üst sınırı %d aşıyor", n, max)
		return nil
	}
	return r.take(int(n))
}

func (r *reader) done() error {
	if r.err != nil {
		return r.err
	}
	if len(r.b) != 0 {
		return fmt.Errorf("%d artık bayt (kanonik olmayan)", len(r.b))
	}
	return nil
}

// ---- karakter kümesi doğrulayıcıları --------------------------------------

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// printableASCII: 0x21-0x7e (boşluk ve denetim karakterleri hariç).
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// validText: geçerli UTF-8 ve NUL yok.
func validText(s string) bool {
	return utf8.ValidString(s) && strings.IndexByte(s, 0) < 0
}

// canonicalUUIDv4: tam 36 karakter, küçük harf, sürüm 4, varyant 8/9/a/b.
func canonicalUUIDv4(s string) bool {
	if len(s) != CommandIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		case 14:
			if c != '4' {
				return false
			}
		case 19:
			if c != '8' && c != '9' && c != 'a' && c != 'b' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
	}
	return true
}

// ValidDeviceID, imza girdisine giren cihaz kimliğinin kanonik biçimini denetler:
// 1..64 bayt, yazdırılabilir ASCII, BÜYÜK HARF YOK (ajan sertifika CN'ini küçük harfe
// çevirerek türetir; karışık harf iki tarafı sessizce ayırırdı).
func ValidDeviceID(s string) bool {
	if len(s) == 0 || len(s) > MaxDeviceIDLen || !printableASCII(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			return false
		}
	}
	return true
}

func validParamKey(k string) bool {
	if len(k) == 0 || len(k) > MaxParamKeyLen {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// ---- params ----------------------------------------------------------------

// ParamsFromMap, sunucu/ajan sınırındaki map[string]any parametrelerini (JSONB / structpb
// sonucu) Param listesine çevirir. Yalnız dize ve dize-listesi kabul edilir; sayı, bool,
// null, iç içe nesne ve karışık liste ReasonMalformedParams ile reddedilir. Çıktı anahtara
// göre sıralıdır.
func ParamsFromMap(m map[string]any) ([]Param, error) {
	out := make([]Param, 0, len(m))
	for k, v := range m {
		switch x := v.(type) {
		case string:
			out = append(out, StringParam(k, x))
		case []string:
			out = append(out, ListParam(k, append([]string(nil), x...)...))
		case []any:
			items := make([]string, 0, len(x))
			for _, it := range x {
				s, ok := it.(string)
				if !ok {
					return nil, newErr(ReasonMalformedParams, "param %q: liste öğesi dize değil (%T)", k, it)
				}
				items = append(items, s)
			}
			out = append(out, ListParam(k, items...))
		default:
			return nil, newErr(ReasonMalformedParams, "param %q: desteklenmeyen tür %T (yalnız dize ve dize listesi)", k, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	if err := ValidateParams(out); err != nil {
		return nil, err
	}
	return out, nil
}

// ValidateParams, parametre kümesinin tüm sınırlarını denetler (imzalamadan ÖNCE ve
// doğrulamada). Hata her zaman ReasonMalformedParams'tır.
func ValidateParams(ps []Param) error {
	if len(ps) > MaxParamKeys {
		return newErr(ReasonMalformedParams, "%d anahtar > %d", len(ps), MaxParamKeys)
	}
	seen := make(map[string]struct{}, len(ps))
	total := 0
	for _, p := range ps {
		if !validParamKey(p.Key) {
			return newErr(ReasonMalformedParams, "geçersiz anahtar %q", p.Key)
		}
		if _, dup := seen[p.Key]; dup {
			return newErr(ReasonMalformedParams, "yinelenen anahtar %q", p.Key)
		}
		seen[p.Key] = struct{}{}
		total += len(p.Key)
		if p.IsList {
			if p.Value != "" {
				return newErr(ReasonMalformedParams, "param %q: liste parametresinde dize değeri", p.Key)
			}
			if len(p.List) > MaxParamListItems {
				return newErr(ReasonMalformedParams, "param %q: %d öğe > %d", p.Key, len(p.List), MaxParamListItems)
			}
			for _, it := range p.List {
				if err := checkParamString(p.Key, it); err != nil {
					return err
				}
				total += len(it)
			}
		} else {
			if len(p.List) != 0 {
				return newErr(ReasonMalformedParams, "param %q: dize parametresinde liste öğeleri", p.Key)
			}
			if err := checkParamString(p.Key, p.Value); err != nil {
				return err
			}
			total += len(p.Value)
		}
		if total > MaxParamsTotalBytes {
			return newErr(ReasonMalformedParams, "toplam param boyutu > %d", MaxParamsTotalBytes)
		}
	}
	return nil
}

func checkParamString(key, s string) error {
	if len(s) > MaxParamStringBytes {
		return newErr(ReasonMalformedParams, "param %q: değer %d bayt > %d", key, len(s), MaxParamStringBytes)
	}
	if !validText(s) {
		return newErr(ReasonMalformedParams, "param %q: geçersiz UTF-8 ya da NUL", key)
	}
	return nil
}

// EncodeParams, params_digest ön-görüntüsünü üretir (anahtarlar bayt sırasıyla):
//
//	LP("kut-cmd-params-v2") || U32(n) || her anahtar için
//	  LP(key) || 0x01 || LP(value)                      (dize)
//	  LP(key) || 0x02 || U32(len) || LP(item)*          (liste)
//
// nil ile boş küme aynı çıktıyı verir.
func EncodeParams(ps []Param) ([]byte, error) {
	if err := ValidateParams(ps); err != nil {
		return nil, err
	}
	sorted := append([]Param(nil), ps...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })
	b := appendLP(nil, DomainParamsV2)
	b = appendU32(b, uint32(len(sorted)))
	for _, p := range sorted {
		b = appendLP(b, p.Key)
		if p.IsList {
			b = append(b, paramTagList)
			b = appendU32(b, uint32(len(p.List)))
			for _, it := range p.List {
				b = appendLP(b, it)
			}
		} else {
			b = append(b, paramTagString)
			b = appendLP(b, p.Value)
		}
	}
	return b, nil
}

// ParamsDigest, SHA-256(EncodeParams(ps)).
func ParamsDigest(ps []Param) ([32]byte, error) {
	enc, err := EncodeParams(ps)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(enc), nil
}

// ParseParams, EncodeParams çıktısını KATI ayrıştırır: etiket tam eşleşmeli, anahtarlar
// kesin artan sırada (yinelenen/sırasız ret), sınırlar aşılmamalı, artık bayt olmamalı.
// Başarılı sonuç için EncodeParams(sonuç) girdiyle bayt-bayt aynıdır.
func ParseParams(b []byte) ([]Param, error) {
	r := &reader{b: b}
	if string(r.lp(len(DomainParamsV2))) != DomainParamsV2 {
		return nil, newErr(ReasonMalformedParams, "etki alanı etiketi uyuşmuyor")
	}
	n := r.u32()
	if r.err == nil && n > MaxParamKeys {
		return nil, newErr(ReasonMalformedParams, "%d anahtar > %d", n, MaxParamKeys)
	}
	var out []Param
	prev := ""
	for i := uint32(0); i < n && r.err == nil; i++ {
		key := string(r.lp(MaxParamKeyLen))
		if r.err != nil {
			break
		}
		if i > 0 && key <= prev {
			if key == prev {
				return nil, newErr(ReasonMalformedParams, "yinelenen anahtar %q", key)
			}
			return nil, newErr(ReasonMalformedParams, "anahtarlar sırasız (%q, %q)", prev, key)
		}
		prev = key
		switch tag := r.byte1(); tag {
		case paramTagString:
			out = append(out, StringParam(key, string(r.lp(MaxParamStringBytes))))
		case paramTagList:
			cnt := r.u32()
			if r.err == nil && cnt > MaxParamListItems {
				return nil, newErr(ReasonMalformedParams, "param %q: %d öğe > %d", key, cnt, MaxParamListItems)
			}
			items := make([]string, 0, cnt)
			for j := uint32(0); j < cnt && r.err == nil; j++ {
				items = append(items, string(r.lp(MaxParamStringBytes)))
			}
			out = append(out, ListParam(key, items...))
		default:
			if r.err == nil {
				return nil, newErr(ReasonMalformedParams, "param %q: bilinmeyen tür etiketi 0x%02x", key, tag)
			}
		}
	}
	if err := r.done(); err != nil {
		return nil, newErr(ReasonMalformedParams, "%v", err)
	}
	if err := ValidateParams(out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---- imzalanan ileti --------------------------------------------------------

// Validate, imzalanan alanların TÜM sınırlarını denetler (imzalamadan önce ve
// doğrulamada AYNI fonksiyon).
func (f Fields) Validate() error {
	if !isLowerHex(f.KeyID, KeyIDHexLen) {
		return newErr(ReasonMalformedEnvelope, "key_id tam %d küçük harfli hex olmalı", KeyIDHexLen)
	}
	if !canonicalUUIDv4(f.CommandID) {
		return newErr(ReasonMalformedEnvelope, "command_id kanonik küçük harfli UUIDv4 değil")
	}
	if !ValidDeviceID(f.DeviceID) {
		return newErr(ReasonBadDeviceID, "device_id kanonik değil (1..%d bayt, yazdırılabilir ASCII, büyük harf yok)", MaxDeviceIDLen)
	}
	if len(f.TenantID) > MaxTenantIDLen || !printableASCII(f.TenantID) {
		return newErr(ReasonMalformedEnvelope, "tenant_id 0..%d bayt yazdırılabilir ASCII olmalı", MaxTenantIDLen)
	}
	if !Known(f.Type) {
		return newErr(ReasonUnknownType, "bilinmeyen komut tipi %q", f.Type)
	}
	if n := len(f.RequestedBy); n < 1 || n > MaxPrincipalLen || !printableASCII(f.RequestedBy) {
		return newErr(ReasonMalformedEnvelope, "requested_by 1..%d bayt yazdırılabilir ASCII olmalı", MaxPrincipalLen)
	}
	if len(f.ApprovedBy) > MaxPrincipalLen || !printableASCII(f.ApprovedBy) {
		return newErr(ReasonMalformedEnvelope, "approved_by 0..%d bayt yazdırılabilir ASCII olmalı", MaxPrincipalLen)
	}
	if f.ApprovedBy != "" && f.ApprovedBy == f.RequestedBy {
		return newErr(ReasonMalformedEnvelope, "approved_by, requested_by ile aynı olamaz")
	}
	if len(f.CorrelationID) > MaxPrincipalLen || !printableASCII(f.CorrelationID) {
		return newErr(ReasonMalformedEnvelope, "correlation_id 0..%d bayt yazdırılabilir ASCII olmalı", MaxPrincipalLen)
	}
	if !isLowerHex(f.Nonce, NonceHexLen) {
		return newErr(ReasonMalformedEnvelope, "nonce tam %d küçük harfli hex olmalı", NonceHexLen)
	}
	if f.IssuedAtNS <= 0 || f.ExpiresAtNS <= f.IssuedAtNS || f.ExpiresAtNS-f.IssuedAtNS > int64(MaxLifetime) {
		return newErr(ReasonBadLifetime, "ömür geçersiz (0 < expires-issued <= %s olmalı)", MaxLifetime)
	}
	return nil
}

// Encode, imzalanan ileti baytlarını üretir (önce Validate):
//
//	LP("kut-cmd-envelope-v2") || LP(key_id) || LP(command_id) || LP(device_id) ||
//	LP(tenant_id) || LP(type) || LP(requested_by) || LP(approved_by) ||
//	LP(correlation_id) || U64(sequence) || LP(nonce) || I64(issued_at_ns) ||
//	I64(expires_at_ns) || LP(params_digest)
func (f Fields) Encode() ([]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return f.encode(), nil
}

func (f Fields) encode() []byte {
	b := make([]byte, 0, 320)
	b = appendLP(b, DomainEnvelopeV2)
	b = appendLP(b, f.KeyID)
	b = appendLP(b, f.CommandID)
	b = appendLP(b, f.DeviceID)
	b = appendLP(b, f.TenantID)
	b = appendLP(b, f.Type)
	b = appendLP(b, f.RequestedBy)
	b = appendLP(b, f.ApprovedBy)
	b = appendLP(b, f.CorrelationID)
	b = appendU64(b, f.Sequence)
	b = appendLP(b, f.Nonce)
	b = appendI64(b, f.IssuedAtNS)
	b = appendI64(b, f.ExpiresAtNS)
	b = appendLPBytes(b, f.ParamsDigest[:])
	return b
}

// ParseCanonicalV2, imzalanan ileti baytlarını KATI ayrıştırır: etiket tam eşleşmeli,
// her alan kendi üst sınırı içinde ve karakter kümesinde olmalı, artık bayt olmamalı.
// Başarılı sonuç için Encode() girdiyle bayt-bayt aynıdır.
func ParseCanonicalV2(b []byte) (Fields, error) {
	r := &reader{b: b}
	var f Fields
	if string(r.lp(len(DomainEnvelopeV2))) != DomainEnvelopeV2 {
		return Fields{}, newErr(ReasonMalformedEnvelope, "etki alanı etiketi uyuşmuyor")
	}
	f.KeyID = string(r.lp(KeyIDHexLen))
	f.CommandID = string(r.lp(CommandIDLen))
	f.DeviceID = string(r.lp(MaxDeviceIDLen))
	f.TenantID = string(r.lp(MaxTenantIDLen))
	f.Type = string(r.lp(MaxTypeLen))
	f.RequestedBy = string(r.lp(MaxPrincipalLen))
	f.ApprovedBy = string(r.lp(MaxPrincipalLen))
	f.CorrelationID = string(r.lp(MaxPrincipalLen))
	f.Sequence = r.u64()
	f.Nonce = string(r.lp(NonceHexLen))
	f.IssuedAtNS = r.i64()
	f.ExpiresAtNS = r.i64()
	if d := r.lp(32); r.err == nil {
		if len(d) != 32 {
			return Fields{}, newErr(ReasonMalformedEnvelope, "params_digest 32 bayt olmalı")
		}
		copy(f.ParamsDigest[:], d)
	}
	if err := r.done(); err != nil {
		return Fields{}, newErr(ReasonMalformedEnvelope, "%v", err)
	}
	if err := f.Validate(); err != nil {
		return Fields{}, err
	}
	return f, nil
}

// Fields, zarf + hedef cihaz kimliğinden imzalanan alanları kurar (params özetini
// hesaplar ve tüm sınırları denetler).
func (e Envelope) Fields(deviceID string) (Fields, error) {
	d, err := ParamsDigest(e.Params)
	if err != nil {
		return Fields{}, err
	}
	f := Fields{
		KeyID: e.KeyID, CommandID: e.CommandID, DeviceID: deviceID, TenantID: e.TenantID,
		Type: e.Type, RequestedBy: e.RequestedBy, ApprovedBy: e.ApprovedBy,
		CorrelationID: e.CorrelationID, Sequence: e.Sequence, Nonce: e.Nonce,
		IssuedAtNS: e.IssuedAtNS, ExpiresAtNS: e.ExpiresAtNS, ParamsDigest: d,
	}
	if err := f.Validate(); err != nil {
		return Fields{}, err
	}
	return f, nil
}

// CanonicalV2, zarfın imzalanan ileti baytlarını döner. deviceID imzalayan için hedef
// cihaz, doğrulayan için ajanın KENDİ kimliğidir; telden gelmez.
func CanonicalV2(deviceID string, e Envelope) ([]byte, error) {
	f, err := e.Fields(deviceID)
	if err != nil {
		return nil, err
	}
	return f.encode(), nil
}

// SignV2, zarfı priv ile imzalar: Version=2, KeyID=KeyID(pub) atanır; önceki imzalar
// silinir. Alanlar geçersizse İMZALANMAZ (sunucu tarafı sınır denetimi).
func SignV2(priv ed25519.PrivateKey, deviceID string, e Envelope) (Envelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Envelope{}, newErr(ReasonUnknownKey, "geçersiz özel anahtar boyutu")
	}
	e.Version = EnvelopeVersion2
	e.KeyID = KeyID(priv.Public().(ed25519.PublicKey))
	e.Signature = nil
	e.ExtraSignatures = nil
	msg, err := CanonicalV2(deviceID, e)
	if err != nil {
		return Envelope{}, err
	}
	e.Signature = ed25519.Sign(priv, msg)
	return e, nil
}

// CoSignV2, aynı iletiyi (KENDİ key_id'si yerleştirilerek) ek imza için imzalar.
func CoSignV2(priv ed25519.PrivateKey, deviceID string, e Envelope) (Signature, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Signature{}, newErr(ReasonUnknownKey, "geçersiz özel anahtar boyutu")
	}
	e.KeyID = KeyID(priv.Public().(ed25519.PublicKey))
	msg, err := CanonicalV2(deviceID, e)
	if err != nil {
		return Signature{}, err
	}
	return Signature{KeyID: e.KeyID, Sig: ed25519.Sign(priv, msg)}, nil
}

// VerifyInput, VerifyV2'nin bağlamıdır.
type VerifyInput struct {
	// DeviceID, doğrulayanın KENDİ kimliğidir (ajanda sertifika CN'i, küçük harf).
	DeviceID string
	// Keys, güvenilen anahtarlardır; yalnız KeyRoleCommand girdileri komut doğrular.
	Keys []KeyEntry
	// Now, güvenilir (sunucuya çıpalı) saattir. Sıfır = senkronsuz → geçici ret.
	Now time.Time
}

// Verified, başarılı bir doğrulamanın sonucudur.
type Verified struct {
	Digest [32]byte // sha256(birincil imzalanan ileti) → CommandResult.envelope_digest
	KeyIDs []string // geçerli sayılan imzaların anahtar kimlikleri
}

// VerifyV2, zarfı durumsuz doğrular. Sıra: sürüm → alan sınırları → imza biçimi →
// anahtar araması (rol/pencere) → imza → zaman. Hatalar tiplidir (*Error).
func VerifyV2(e Envelope, in VerifyInput) (Verified, error) {
	if e.Version != EnvelopeVersion2 {
		return Verified{}, newErr(ReasonUnsupportedVersion, "envelope_version=%d", e.Version)
	}
	f, err := e.Fields(in.DeviceID)
	if err != nil {
		return Verified{}, err
	}
	if len(e.Signature) != SignatureLen {
		return Verified{}, newErr(ReasonMalformedEnvelope, "birincil imza %d bayt olmalı (var: %d)", SignatureLen, len(e.Signature))
	}
	if len(e.ExtraSignatures) > MaxExtraSignatures {
		return Verified{}, newErr(ReasonMalformedEnvelope, "%d ek imza > %d", len(e.ExtraSignatures), MaxExtraSignatures)
	}
	type cand struct {
		keyID string
		sig   []byte
	}
	cands := []cand{{e.KeyID, e.Signature}}
	seen := map[string]bool{e.KeyID: true}
	for _, x := range e.ExtraSignatures {
		if !isLowerHex(x.KeyID, KeyIDHexLen) || len(x.Sig) != SignatureLen {
			return Verified{}, newErr(ReasonMalformedEnvelope, "ek imza biçimi geçersiz")
		}
		if seen[x.KeyID] {
			return Verified{}, newErr(ReasonMalformedEnvelope, "yinelenen imza anahtarı %s", x.KeyID)
		}
		seen[x.KeyID] = true
		cands = append(cands, cand{x.KeyID, x.Sig})
	}

	keys := commandKeyIndex(in.Keys)
	var good []string
	var sawBad, sawExpired bool
	for _, c := range cands {
		k, ok := keys[c.keyID]
		if !ok {
			continue
		}
		if k.NotAfterNS == 0 || f.IssuedAtNS < k.NotBeforeNS || f.IssuedAtNS > k.NotAfterNS {
			sawExpired = true
			continue
		}
		ff := f
		ff.KeyID = c.keyID
		if ed25519.Verify(k.Pub, ff.encode(), c.sig) {
			good = append(good, c.keyID)
		} else {
			sawBad = true
		}
	}
	if len(good) < RequiredSignatures(e.Type) {
		switch {
		case sawBad:
			return Verified{}, newErr(ReasonBadSignature, "imza doğrulanamadı")
		case sawExpired:
			return Verified{}, newErr(ReasonKeyExpired, "anahtar issued_at anında geçerli değil")
		default:
			return Verified{}, newErr(ReasonUnknownKey, "güvenilen komut anahtarı yok")
		}
	}

	if in.Now.IsZero() {
		return Verified{}, newErr(ReasonClockUnsynced, "güvenilir saat yok")
	}
	now := in.Now.UnixNano()
	if f.IssuedAtNS > now+int64(ClockSkew) {
		return Verified{}, newErr(ReasonNotYetValid, "issued_at gelecekte")
	}
	if now > f.ExpiresAtNS {
		return Verified{}, newErr(ReasonExpired, "zarf süresi doldu")
	}
	return Verified{Digest: sha256.Sum256(f.encode()), KeyIDs: good}, nil
}

// commandKeyIndex, güvenilen anahtar listesinden yalnız KOMUT rolündeki, kimliği
// açık anahtardan türeyen girdileri indeksler. Aynı kimlik iki kez görünürse belirsizlik
// fail-closed çözülür (ikisi de atılır).
func commandKeyIndex(keys []KeyEntry) map[string]KeyEntry {
	idx := make(map[string]KeyEntry, len(keys))
	dup := map[string]bool{}
	for _, k := range keys {
		if k.Role != KeyRoleCommand || len(k.Pub) != ed25519.PublicKeySize {
			continue
		}
		id := KeyID(k.Pub)
		if _, ok := idx[id]; ok {
			dup[id] = true
			continue
		}
		k.KeyID = id
		idx[id] = k
	}
	for id := range dup {
		delete(idx, id)
	}
	return idx
}
