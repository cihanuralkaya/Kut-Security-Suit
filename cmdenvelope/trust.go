package cmdenvelope

// Güven bildirimi (TrustStatement) — "Signed Command Fabric" (dondurulmuş).
//
// Bir bildirim, cihazın hangi anahtarlara güveneceğini söyler: KÖK (ROOT) anahtarlar
// yalnız bildirim imzalar (çevrimdışı tutulur), KOMUT (COMMAND) anahtarlar yalnız
// komut zarfı imzalar ve her birinin son kullanma zamanı vardır. Kabul kuralları
// ApplyStatement içinde SAF fonksiyon olarak tek yerde tutulur; ajan ve araçlar aynı
// kodu kullanır.

import (
	"crypto/ed25519"
	"sort"
	"strings"
	"time"
)

// Güven bildirimi sınırları.
const (
	MaxStatementKeys = 32
	MaxVerifyMode    = 2 // 0 none, 1 warn, 2 enforce
)

// KeyRole, bir anahtarın rolüdür (kodlamada U32).
type KeyRole uint32

const (
	KeyRoleRoot    KeyRole = 1 // yalnız bildirim imzalar
	KeyRoleCommand KeyRole = 2 // yalnız komut zarfı imzalar; NotAfterNS ZORUNLU
	// KeyRoleApprover, çift kontrollü komutlarda ikinci (onaylayan) imzayı atar; NotAfterNS
	// ZORUNLU. Onaylayan imzası yalnız VerifyInput.MinSignatures sayısına katılır: en az bir
	// KOMUT anahtarı imzası her zaman gerekir, yani onaylayan tek başına komut kabul ettiremez.
	// Onaylayan anahtarı bildirim imzalayamaz.
	KeyRoleApprover KeyRole = 3
)

// Rol uyumluluk kuralı: bilinmeyen bir rol (1, 2, 3 dışı) içeren bildirim TAMAMEN reddedilir
// (malformed_statement); bildirim kısmen yorumlanmaz. Yeni bir rol eklemek yeni bir yük türü
// sürümü (trust.v3) gerektirir; eski ajanlar o halkayı atlar (bkz. ApplyChainDSSE).

// KeyEntry, bildirimdeki tek bir anahtardır. NotAfterNS==0 "süresiz" demektir ve yalnız
// KÖK anahtarlarda geçerlidir.
type KeyEntry struct {
	KeyID       string
	Pub         ed25519.PublicKey
	Role        KeyRole
	NotBeforeNS int64
	NotAfterNS  int64
}

// Statement, güven bildirimidir. İmza İÇERMEYEN alanlar kanonik ileti olarak imzalanır.
type Statement struct {
	Epoch         uint64
	Keys          []KeyEntry
	RootThreshold uint32
	IssuedAtNS    int64
	MinVerifyMode uint32
	MinAgentBuild uint64
	Signatures    []DSSESignature
}

func (k KeyEntry) inWindow(at int64) bool {
	return at >= k.NotBeforeNS && (k.NotAfterNS == 0 || at <= k.NotAfterNS)
}

// Validate, bildirimin YAPISAL değişmezlerini denetler (imza doğrulaması yapmaz).
func (st Statement) Validate() error {
	bad := func(format string, a ...any) error { return newErr(ReasonMalformedStatement, format, a...) }
	if st.Epoch == 0 {
		return bad("epoch >= 1 olmalı")
	}
	if st.IssuedAtNS <= 0 {
		return bad("issued_at_ns > 0 olmalı")
	}
	if st.MinVerifyMode > MaxVerifyMode {
		return bad("min_verify_mode %d > %d", st.MinVerifyMode, MaxVerifyMode)
	}
	if n := len(st.Keys); n < 1 || n > MaxStatementKeys {
		return bad("anahtar sayısı %d (1..%d olmalı)", n, MaxStatementKeys)
	}
	seen := make(map[string]struct{}, len(st.Keys))
	roots := 0
	for _, k := range st.Keys {
		if len(k.Pub) != ed25519.PublicKeySize || k.KeyID != KeyID(k.Pub) {
			return bad("anahtar kimliği açık anahtardan türemiyor (%q)", k.KeyID)
		}
		if IsWeakPublicKey(k.Pub) {
			return bad("anahtar %s: zayıf (küçük mertebeli ya da kanonik olmayan) açık anahtar", k.KeyID)
		}
		if _, dup := seen[k.KeyID]; dup {
			return bad("yinelenen anahtar %s", k.KeyID)
		}
		seen[k.KeyID] = struct{}{}
		switch k.Role {
		case KeyRoleRoot:
			roots++
		case KeyRoleCommand, KeyRoleApprover:
			if k.NotAfterNS == 0 {
				return bad("komut/onaylayan anahtarı %s için not_after zorunlu", k.KeyID)
			}
		default:
			return bad("anahtar %s: bilinmeyen rol %d", k.KeyID, k.Role)
		}
		if k.NotBeforeNS < 0 || k.NotAfterNS < 0 || (k.NotAfterNS != 0 && k.NotAfterNS <= k.NotBeforeNS) {
			return bad("anahtar %s: geçersiz geçerlilik penceresi", k.KeyID)
		}
	}
	if roots < 1 || st.RootThreshold < 1 || int(st.RootThreshold) > roots {
		return bad("root_threshold %d (1..%d kök anahtar olmalı)", st.RootThreshold, roots)
	}
	if len(st.Signatures) > MaxDSSESignatures {
		return bad("%d imza > %d", len(st.Signatures), MaxDSSESignatures)
	}
	for _, s := range st.Signatures {
		if !isLowerHex(s.KeyID, KeyIDHexLen) || len(s.Sig) != SignatureLen {
			return bad("imza biçimi geçersiz")
		}
	}
	return nil
}

// CanonicalStatement, imzalanan ileti baytlarını üretir (anahtarlar key_id sırasıyla):
//
//	LP("kut-cmd-trust-v2") || U64(epoch) || U32(root_threshold) || I64(issued_at_ns) ||
//	U32(min_verify_mode) || U64(min_agent_build) || U32(n) ||
//	  her anahtar: LP(key_id) || LP(pubkey) || U32(role) || I64(not_before) || I64(not_after)
//
// İmzalar iletiye DAHİL DEĞİLDİR; tüm imzacılar aynı baytları imzalar.
func CanonicalStatement(st Statement) ([]byte, error) {
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return encodeStatement(st), nil
}

func encodeStatement(st Statement) []byte {
	keys := append([]KeyEntry(nil), st.Keys...)
	sort.Slice(keys, func(i, j int) bool { return keys[i].KeyID < keys[j].KeyID })
	b := make([]byte, 0, 96+len(keys)*100)
	b = appendLP(b, DomainTrustV2)
	b = appendU64(b, st.Epoch)
	b = appendU32(b, st.RootThreshold)
	b = appendI64(b, st.IssuedAtNS)
	b = appendU32(b, st.MinVerifyMode)
	b = appendU64(b, st.MinAgentBuild)
	b = appendU32(b, uint32(len(keys)))
	for _, k := range keys {
		b = appendLP(b, k.KeyID)
		b = appendLPBytes(b, k.Pub)
		b = appendU32(b, uint32(k.Role))
		b = appendI64(b, k.NotBeforeNS)
		b = appendI64(b, k.NotAfterNS)
	}
	return b
}

// ParseStatement, kanonik bildirim iletisini KATI ayrıştırır (imzasız): etiket tam
// eşleşmeli, anahtarlar kesin artan key_id sırasında (yinelenen/sırasız ret), sınırlar
// aşılmamalı, artık bayt olmamalı. Başarılı sonuç için CanonicalStatement(sonuç)
// girdiyle bayt-bayt aynıdır.
func ParseStatement(b []byte) (Statement, error) {
	r := &reader{b: b}
	var st Statement
	if string(r.lp(len(DomainTrustV2))) != DomainTrustV2 {
		return Statement{}, newErr(ReasonMalformedStatement, "etki alanı etiketi uyuşmuyor")
	}
	st.Epoch = r.u64()
	st.RootThreshold = r.u32()
	st.IssuedAtNS = r.i64()
	st.MinVerifyMode = r.u32()
	st.MinAgentBuild = r.u64()
	n := r.u32()
	if r.err == nil && n > MaxStatementKeys {
		return Statement{}, newErr(ReasonMalformedStatement, "%d anahtar > %d", n, MaxStatementKeys)
	}
	prev := ""
	for i := uint32(0); i < n && r.err == nil; i++ {
		var k KeyEntry
		k.KeyID = string(r.lp(KeyIDHexLen))
		k.Pub = ed25519.PublicKey(append([]byte(nil), r.lp(ed25519.PublicKeySize)...))
		k.Role = KeyRole(r.u32())
		k.NotBeforeNS = r.i64()
		k.NotAfterNS = r.i64()
		if r.err != nil {
			break
		}
		if i > 0 && k.KeyID <= prev {
			return Statement{}, newErr(ReasonMalformedStatement, "anahtarlar sırasız ya da yinelenen (%s)", k.KeyID)
		}
		prev = k.KeyID
		st.Keys = append(st.Keys, k)
	}
	if err := r.done(); err != nil {
		return Statement{}, newErr(ReasonMalformedStatement, "%v", err)
	}
	if err := st.Validate(); err != nil {
		return Statement{}, err
	}
	return st, nil
}

// SignStatement, bildirimi priv ile imzalayıp imzayı ekleyen BİR KOPYA döner (aynı
// anahtarın önceki imzası değiştirilir). Kök özel anahtarı yalnız çevrimdışı araçta
// kullanılır; C2 bu fonksiyonu çağırmaz.
func SignStatement(priv ed25519.PrivateKey, st Statement) (Statement, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Statement{}, newErr(ReasonMalformedStatement, "geçersiz özel anahtar boyutu")
	}
	st.Signatures = append([]DSSESignature(nil), st.Signatures...)
	body, err := CanonicalStatement(st)
	if err != nil {
		return Statement{}, err
	}
	id := KeyID(priv.Public().(ed25519.PublicKey))
	sig := DSSESignature{KeyID: id, Sig: ed25519.Sign(priv, PAE(PayloadTypeTrust, body))}
	for i := range st.Signatures {
		if st.Signatures[i].KeyID == id {
			st.Signatures[i] = sig
			return st, nil
		}
	}
	st.Signatures = append(st.Signatures, sig)
	return st, nil
}

// AcceptMode, bildirimin hangi kuralla kabul edildiğidir.
type AcceptMode string

const (
	// AcceptPin: sabitlenmiş (pin) kök anahtar imzaladı; local'den büyük HER epoch kabul.
	AcceptPin AcceptMode = "pin"
	// AcceptChain: epoch == local+1 ve mevcut kök eşiği (+ kök kümesi değiştiyse yeni
	// kümenin eşiği) imzaladı.
	AcceptChain AcceptMode = "chain"
	// AcceptBootstrap: yerel durum ve pin yok; bildirim kendi kök eşiğiyle tutarlı. Bu
	// kabul YALNIZ çağıranın ek koşulları (sunucu opt-in, sunset, SPKI pin) sağlanırsa
	// geçerlidir; bu fonksiyon onları denetlemez.
	AcceptBootstrap AcceptMode = "bootstrap"
)

// Acceptance, kabul edilen bildirimin sonucudur.
type Acceptance struct {
	Mode      AcceptMode
	EpochJump bool // epoch, local+1'den büyük (yalnız pin imzasıyla mümkün)
	Statement Statement
}

// Floors, ajanın yalnız YUKARI doğru ratchet eden eşikleridir (kural 6). Bildirimdeki
// değerler düşük olsa bile eşik düşmez.
type Floors struct {
	MinVerifyMode uint32
	MinAgentBuild uint64
}

// Raise, bildirimdeki eşiklerle max alır.
func (f Floors) Raise(st Statement) Floors {
	if st.MinVerifyMode > f.MinVerifyMode {
		f.MinVerifyMode = st.MinVerifyMode
	}
	if st.MinAgentBuild > f.MinAgentBuild {
		f.MinAgentBuild = st.MinAgentBuild
	}
	return f
}

// ApplyStatement, bir bildirimin yerel durum (local; nil = hiç güven edinilmemiş) üzerine
// uygulanıp uygulanamayacağına karar veren SAF fonksiyondur. Kurallar:
//
//  1. İmzacılar KÖK rolünde olmalı; komut anahtarları bildirim imzalayamaz.
//  2. Pin kuralı: pins kümesinden ≥1 anahtarın imzası, local'den büyük HER epoch'u kabul
//     ettirir (epoch atlaması = tek adımlı kurtarma).
//  3. Zincir kuralı: epoch == local.Epoch+1 ve local'in kök kümesinden ≥ local.RootThreshold
//     ayrık anahtar imzalamış; kök kümesi değişiyorsa yeni kümeden ≥ st.RootThreshold ayrık
//     anahtar da imzalamış. Aynı key_id bir kez sayılır.
//  4. Bootstrap: local de pin de yoksa bildirim kendi kök eşiğiyle tutarlı olmalı. Pin varken
//     pin imzasız ilk bildirim reddedilir (ReasonPinRequired).
//  5. İmzacı penceresi bildirimin KENDİ issued_at_ns anında değerlendirilir (süresi
//     dolmuş kök anahtarın imzası sayılmaz); issued_at_ns, now+2dk'dan ileride olamaz.
//     Zincir kuralında ek olarak issued_at_ns, yerel bildirimin issued_at_ns değerinden
//     küçük olamaz (ReasonBackdated): süresi dolmuş bir anahtar eski bir pencereye geriye
//     tarihli bildirim imzalayamaz. Pin kuralı bu denetimden muaftır.
//  6. Güvenilir saat (now) sıfırsa pin dışındaki her kabul geçici ReasonClockUnsynced ile
//     reddedilir; gelecek-tarih denetimi asla atlanarak kabul verilmez.
//
// Epoch hiçbir zaman azalmaz (st.Epoch <= local.Epoch → ReasonStaleEpoch). Eşik ratchet'i
// için Floors.Raise kullanılır.
func ApplyStatement(local *Statement, st Statement, pins []ed25519.PublicKey, now time.Time) (Acceptance, error) {
	if err := st.Validate(); err != nil {
		return Acceptance{}, err
	}
	var localEpoch uint64
	if local != nil {
		if err := local.Validate(); err != nil {
			return Acceptance{}, newErr(ReasonMalformedStatement, "yerel durum geçersiz: %v", err)
		}
		localEpoch = local.Epoch
	}
	if !now.IsZero() && st.IssuedAtNS > now.UnixNano()+int64(ClockSkew) {
		return Acceptance{}, newErr(ReasonNotYetValid, "bildirim issued_at gelecekte")
	}
	if st.Epoch <= localEpoch {
		return Acceptance{}, newErr(ReasonStaleEpoch, "epoch %d <= yerel %d", st.Epoch, localEpoch)
	}
	msg := PAE(PayloadTypeTrust, encodeStatement(st))

	if pinSigned(msg, st.Signatures, pins) {
		return Acceptance{Mode: AcceptPin, EpochJump: st.Epoch != localEpoch+1, Statement: st}, nil
	}

	if now.IsZero() {
		return Acceptance{}, newErr(ReasonClockUnsynced, "güvenilir saat yok: pin imzasız bildirim kabul edilemez")
	}

	if local == nil {
		if len(pins) > 0 {
			return Acceptance{}, newErr(ReasonPinRequired, "pin tanımlıyken ilk bildirim pin ile imzalı olmalı")
		}
		if err := quorum(msg, st, rootsOf(st.Keys), st.RootThreshold, st.IssuedAtNS, "bildirimin kendi kök kümesi", nonRootsOf(st.Keys)); err != nil {
			return Acceptance{}, err
		}
		return Acceptance{Mode: AcceptBootstrap, Statement: st}, nil
	}

	if st.Epoch != local.Epoch+1 {
		return Acceptance{}, newErr(ReasonEpochSkipped, "epoch %d, beklenen %d (atlama yalnız pin imzasıyla)", st.Epoch, local.Epoch+1)
	}
	if st.IssuedAtNS < local.IssuedAtNS {
		return Acceptance{}, newErr(ReasonBackdated, "issued_at %d, yerel bildirimin %d değerinden önce", st.IssuedAtNS, local.IssuedAtNS)
	}
	oldRoots := rootsOf(local.Keys)
	if err := quorum(msg, st, oldRoots, local.RootThreshold, st.IssuedAtNS, "mevcut kök kümesi", nonRootsOf(local.Keys)); err != nil {
		return Acceptance{}, err
	}
	if !sameKeySet(oldRoots, rootsOf(st.Keys)) {
		if err := quorum(msg, st, rootsOf(st.Keys), st.RootThreshold, st.IssuedAtNS, "yeni kök kümesi", nonRootsOf(st.Keys)); err != nil {
			return Acceptance{}, err
		}
	}
	return Acceptance{Mode: AcceptChain, Statement: st}, nil
}

// ApplyChain, bildirimleri SIRAYLA uygular (kural 7). İlk başarısız halkada durur;
// dönen durum son başarılı halkadır (hiç halka uygulanmadıysa local aynen döner) ve
// applied başarılı halka sayısıdır — çağıran her halkayı kalıcılaştırıp aynı noktadan
// yeniden deneyebilir.
func ApplyChain(local *Statement, sts []Statement, pins []ed25519.PublicKey, now time.Time) (*Statement, int, error) {
	cur := local
	for i, st := range sts {
		acc, err := ApplyStatement(cur, st, pins, now)
		if err != nil {
			return cur, i, err
		}
		s := acc.Statement
		cur = &s
	}
	return cur, len(sts), nil
}

// SkippedEntry, ApplyChainDSSE'nin atladığı bir zincir girdisidir.
type SkippedEntry struct {
	Index       int    // girdinin zincirdeki sırası (0 tabanlı)
	PayloadType string // desteklenmeyen yük türü
	Reason      Reason // unsupported_version (tanınan önek, başka sürüm) ya da bad_payload_type
}

// ChainResult, ApplyChainDSSE'nin sonucudur.
type ChainResult struct {
	State   *Statement     // son başarılı halka (hiç uygulanmadıysa local aynen)
	Applied int            // uygulanan halka sayısı
	Skipped []SkippedEntry // atlanan (desteklenmeyen yük türlü) girdiler
}

// ApplyChainDSSE, DSSE zarflarından oluşan bir zinciri SIRAYLA uygular. Yük türü
// PayloadTypeTrust olmayan girdiler (ör. gelecekteki bir trust.v3) durumu değiştirmeden ATLANIR ve
// zincir desteklenen girdilerle sürer: bu ajanın anlayamadığı bir halka, sonraki
// halkaların uygulanmasını engellemez. Atlama hiçbir şey kabul ettirmez ve epoch
// ilerletmez; atlanan halkaya bağlı bir sonraki v2 halka epoch kuralından (epoch_skipped)
// doğal olarak reddedilir. Yük türü DOĞRU ama içeriği geçersiz ya da kabul edilemeyen bir
// girdi ise zincir orada durur (ApplyChain gibi). Sunucu, ajanın bildirdiği yeteneklere
// (capabilities) göre yalnız desteklenen halkaları göndermelidir; atlama ikinci savunmadır.
func ApplyChainDSSE(local *Statement, entries []DSSE, pins []ed25519.PublicKey, now time.Time) (ChainResult, error) {
	res := ChainResult{State: local}
	for i, d := range entries {
		if d.PayloadType != PayloadTypeTrust {
			reason := ReasonBadPayloadType
			if strings.HasPrefix(d.PayloadType, payloadTypeTrustPrefix) {
				reason = ReasonUnsupportedVersion
			}
			res.Skipped = append(res.Skipped, SkippedEntry{Index: i, PayloadType: d.PayloadType, Reason: reason})
			continue
		}
		acc, err := ApplyStatementDSSE(res.State, d, pins, now)
		if err != nil {
			return res, err
		}
		s := acc.Statement
		res.State = &s
		res.Applied++
	}
	return res, nil
}

// VerifyChain, sunucunun zincir dosyasını doğrular: epoch'lar tam olarak 1..N olmalı ve
// her halka ApplyStatement'ı geçmeli. pins boşsa epoch 1 kendi eşiğiyle tutarlı olmalı
// (dosyanın iç tutarlılığı); doluysa pin imzalı olmalı. Dönen değer güncel bildirimdir.
func VerifyChain(sts []Statement, pins []ed25519.PublicKey, now time.Time) (Statement, error) {
	if len(sts) == 0 {
		return Statement{}, newErr(ReasonChainIncomplete, "zincir boş")
	}
	for i, st := range sts {
		if st.Epoch != uint64(i)+1 {
			return Statement{}, newErr(ReasonChainIncomplete, "%d. halkanın epoch'u %d, beklenen %d", i+1, st.Epoch, i+1)
		}
	}
	cur, n, err := ApplyChain(nil, sts, pins, now)
	if err != nil {
		return Statement{}, newErr(ReasonOf(err), "halka %d: %v", n+1, err)
	}
	return *cur, nil
}

// ChainKeyValid, bir anahtarın (örn. sunucunun Aktif komut anahtarı) VERİLEN güncel
// bildirimde şu an komut imzalamaya uygun olup olmadığını denetler: bildirimde KOMUT rolüyle
// bulunmalı ve now pencere içinde olmalı. Önyükleme öz-denetimi ve yürütme anı denetimi.
func ChainKeyValid(current Statement, keyID string, now time.Time) (KeyEntry, error) {
	for _, k := range current.Keys {
		if k.KeyID != keyID {
			continue
		}
		if k.Role != KeyRoleCommand {
			return KeyEntry{}, newErr(ReasonKeyNotInChain, "anahtar %s komut rolünde değil", keyID)
		}
		if now.IsZero() {
			return KeyEntry{}, newErr(ReasonClockUnsynced, "güvenilir saat yok")
		}
		n := now.UnixNano()
		if n < k.NotBeforeNS {
			return KeyEntry{}, newErr(ReasonNotYetValid, "anahtar %s henüz geçerli değil", keyID)
		}
		if k.NotAfterNS == 0 || n > k.NotAfterNS {
			return KeyEntry{}, newErr(ReasonKeyExpired, "anahtar %s süresi doldu", keyID)
		}
		return k, nil
	}
	return KeyEntry{}, newErr(ReasonKeyNotInChain, "anahtar %s güncel bildirimde yok", keyID)
}

// ActiveKeyValid, zinciri (VerifyChain) doğrular ve pub anahtarının GÜNCEL bildirimde
// geçerli bir komut anahtarı olduğunu denetler (sunucu önyükleme öz-denetimi).
func ActiveKeyValid(chain []Statement, pins []ed25519.PublicKey, pub ed25519.PublicKey, now time.Time) error {
	cur, err := VerifyChain(chain, pins, now)
	if err != nil {
		return err
	}
	_, err = ChainKeyValid(cur, KeyID(pub), now)
	return err
}

// ---- iç yardımcılar ---------------------------------------------------------

func pinSigned(msg []byte, sigs []DSSESignature, pins []ed25519.PublicKey) bool {
	if len(pins) == 0 {
		return false
	}
	byID := make(map[string]ed25519.PublicKey, len(pins))
	for _, p := range pins {
		if IsWeakPublicKey(p) {
			continue // zayıf pin güven kümesine alınmaz
		}
		if id := KeyID(p); id != "" {
			byID[id] = p
		}
	}
	for _, s := range sigs {
		if p, ok := byID[s.KeyID]; ok && ed25519.Verify(p, msg, s.Sig) {
			return true
		}
	}
	return false
}

func rootsOf(keys []KeyEntry) map[string]KeyEntry {
	m := map[string]KeyEntry{}
	for _, k := range keys {
		if k.Role == KeyRoleRoot {
			m[k.KeyID] = k
		}
	}
	return m
}

// nonRootsOf, KÖK olmayan (komut ve onaylayan) anahtarlardır; yalnız signer_not_root teşhisi içindir.
func nonRootsOf(keys []KeyEntry) map[string]KeyEntry {
	m := map[string]KeyEntry{}
	for _, k := range keys {
		if k.Role == KeyRoleCommand || k.Role == KeyRoleApprover {
			m[k.KeyID] = k
		}
	}
	return m
}

func sameKeySet(a, b map[string]KeyEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for id, ka := range a {
		kb, ok := b[id]
		if !ok || !ed25519.PublicKey(ka.Pub).Equal(kb.Pub) {
			return false
		}
	}
	return true
}

// validSigners, imzalar içinden roots kümesindeki, penceresi at anını kapsayan ve doğrulanan
// AYRIK anahtar sayısını döner.
func validSigners(msg []byte, sigs []DSSESignature, signers map[string]KeyEntry, at int64) int {
	counted := map[string]bool{}
	for _, s := range sigs {
		k, ok := signers[s.KeyID]
		if !ok || counted[s.KeyID] || !k.inWindow(at) {
			continue
		}
		if ed25519.Verify(k.Pub, msg, s.Sig) {
			counted[s.KeyID] = true
		}
	}
	return len(counted)
}

// quorum, roots kümesinden ≥ need ayrık geçerli imza arar; yoksa tipli hata döner.
// Hiç kök imzası yokken geçerli bir KOMUT anahtarı imzası varsa neden ReasonSignerNotRoot'tur.
func quorum(msg []byte, st Statement, roots map[string]KeyEntry, need uint32, at int64, label string, commands map[string]KeyEntry) error {
	got := validSigners(msg, st.Signatures, roots, at)
	if uint32(got) >= need {
		return nil
	}
	if got == 0 && validSigners(msg, st.Signatures, commands, at) > 0 {
		return newErr(ReasonSignerNotRoot, "bildirimi yalnız komut anahtarı imzalamış (kök rolü şart)")
	}
	return newErr(ReasonThresholdNotMet, "%s: %d/%d geçerli kök imzası", label, got, need)
}

// ---- DSSE gösterimi ---------------------------------------------------------------

// DSSE, bildirimi DSSE zarfı olarak döner: payloadType "application/vnd.kut.trust.v2", gövde =
// kanonik bildirim iletisi, imzalar = st.Signatures (KÖK anahtarlar; keyid doğrulanmamış ipucu).
func (st Statement) DSSE() (DSSE, error) {
	body, err := CanonicalStatement(st)
	if err != nil {
		return DSSE{}, err
	}
	return DSSE{PayloadType: PayloadTypeTrust, Payload: body, Signatures: append([]DSSESignature(nil), st.Signatures...)}, nil
}

// ParseStatementDSSE, DSSE zarfını Statement'a çevirir: yük türü tam eşleşmeli (başka bir
// nesne türü ya da sürüm reddedilir), gövde KATI ayrıştırılır, imza girdileri biçim denetiminden
// geçer. İmzaları doğrulamaz; kabul ApplyStatement'tadır.
func ParseStatementDSSE(d DSSE) (Statement, error) {
	if d.PayloadType != PayloadTypeTrust {
		if strings.HasPrefix(d.PayloadType, payloadTypeTrustPrefix) {
			return Statement{}, newErr(ReasonUnsupportedVersion, "payloadType=%q", d.PayloadType)
		}
		return Statement{}, newErr(ReasonBadPayloadType, "payloadType=%q", d.PayloadType)
	}
	if err := d.validateShape(ReasonMalformedStatement); err != nil {
		return Statement{}, err
	}
	st, err := ParseStatement(d.Payload)
	if err != nil {
		return Statement{}, err
	}
	st.Signatures = append([]DSSESignature(nil), d.Signatures...)
	return st, nil
}

// ApplyStatementDSSE = ParseStatementDSSE + ApplyStatement.
func ApplyStatementDSSE(local *Statement, d DSSE, pins []ed25519.PublicKey, now time.Time) (Acceptance, error) {
	st, err := ParseStatementDSSE(d)
	if err != nil {
		return Acceptance{}, err
	}
	return ApplyStatement(local, st, pins, now)
}
