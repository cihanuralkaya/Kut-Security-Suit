package cmdenvelope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
)

const (
	tDevice  = "0b1c2d3e-4f50-4a61-8b72-93a4b5c6d7e8"
	tDevice2 = "1c2d3e4f-5061-4b72-9c83-a4b5c6d7e8f9"
	tBase    = int64(1_790_000_000_000_000_000) // sabit referans an (ns)
)

func tKey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("kut-w2-test-seed:" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func tPub(name string) ed25519.PublicKey { return tKey(name).Public().(ed25519.PublicKey) }

// tCmdKeys: cmdA geçerli [base-1h, base+90d].
func tCmdKeys(names ...string) []KeyEntry {
	var out []KeyEntry
	for _, n := range names {
		p := tPub(n)
		out = append(out, KeyEntry{KeyID: KeyID(p), Pub: p, Role: KeyRoleCommand,
			NotBeforeNS: tBase - int64(time.Hour), NotAfterNS: tBase + int64(90*24*time.Hour)})
	}
	return out
}

func tNow() time.Time { return time.Unix(0, tBase+int64(time.Minute)) }

func tEnv() Envelope {
	return Envelope{
		KeyID: KeyID(tPub("cmdA")), CommandID: "a1b2c3d4-e5f6-4a07-98a9-b0c1d2e3f4a5", TenantID: "acme", Type: TypeQuarantine,
		RequestedBy: "admin:9f8e7d6c-5b4a-4392-8180-706f5e4d3c2b", CorrelationID: "req-0001",
		Sequence: 7, Nonce: "00112233445566778899aabbccddeeff",
		IssuedAtNS: tBase, ExpiresAtNS: tBase + int64(7*24*time.Hour),
		Params: []Param{StringParam("reason", "ransomware"), ListParam("paths", "a", "b")},
	}
}

func tSigned(t *testing.T) Envelope {
	t.Helper()
	e, err := SignV2(tKey("cmdA"), tDevice, tEnv())
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func tVerify(e Envelope, dev string, now time.Time, keys ...string) (Verified, error) {
	return VerifyV2(e, VerifyInput{DeviceID: dev, Keys: tCmdKeys(keys...), Now: now})
}

func wantReason(t *testing.T, err error, want Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("hata bekleniyordu (%s)", want)
	}
	if got := ReasonOf(err); got != want {
		t.Fatalf("neden %q, beklenen %q (%v)", got, want, err)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	e := tSigned(t)
	v, err := tVerify(e, tDevice, tNow(), "cmdA")
	if err != nil {
		t.Fatal(err)
	}
	if len(v.KeyIDs) != 1 || v.KeyIDs[0] != e.KeyID {
		t.Fatalf("anahtar kimlikleri: %v", v.KeyIDs)
	}
	msg, _ := CanonicalV2(tDevice, e)
	if v.Digest != sha256.Sum256(msg) {
		t.Fatal("envelope_digest = sha256(ileti) değil")
	}
	if len(e.KeyID) != 32 || e.KeyID != KeyID(tPub("cmdA")) {
		t.Fatalf("key_id 128-bit hex değil: %q", e.KeyID)
	}
}

// N01 (yerel yarı): kanonik bayt sabitleri; paylaşılan vektör dosyası vectors_test.go'da.
func TestCanonicalV2_FixedLayout(t *testing.T) {
	e := tSigned(t)
	msg, err := CanonicalV2(tDevice, e)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(msg, append([]byte{0, 0, 0, 19}, "kut-cmd-envelope-v2"...)) {
		t.Fatalf("etiket öneki hatalı: %x", msg[:24])
	}
	f, err := ParseCanonicalV2(msg)
	if err != nil {
		t.Fatal(err)
	}
	if f.Sequence != 7 || f.DeviceID != tDevice || f.TenantID != "acme" || f.KeyID != e.KeyID {
		t.Fatalf("ayrıştırma sonucu hatalı: %+v", f)
	}
	again, _ := f.Encode()
	if !bytes.Equal(again, msg) {
		t.Fatal("Parse→Encode bayt-bayt aynı değil")
	}
}

// N02: 0x1f içeren requested_by reddedilir; bitişik alanlar arasında bayt kaydırma farklı
// bayt üretir (uzunluk önekli kodlama).
func TestN02_LengthPrefixedFieldsDoNotAlias(t *testing.T) {
	e := tEnv()
	e.RequestedBy = "admin:x\x1fy"
	if _, err := SignV2(tKey("cmdA"), tDevice, e); err == nil {
		t.Fatal("0x1f içeren requested_by imzalanmamalı")
	}
	a, b := tEnv(), tEnv()
	a.RequestedBy, a.CorrelationID = "ab", "c"
	b.RequestedBy, b.CorrelationID = "a", "bc"
	ma, _ := CanonicalV2(tDevice, a)
	mb, _ := CanonicalV2(tDevice, b)
	if bytes.Equal(ma, mb) {
		t.Fatal("bitişik alanlar arası bayt kaydırma aynı ileti üretti")
	}
	a, b = tEnv(), tEnv()
	a.TenantID, a.Type = "", TypeLock
	b.TenantID, b.Type = "L", "OCK"
	if _, err := CanonicalV2(tDevice, b); err == nil {
		t.Fatal("geçersiz tip imzalanmamalı")
	}
}

// N03/N04/N05: params özet ayrımları.
func TestN03_N05_ParamsDigest(t *testing.T) {
	d := func(ps ...Param) [32]byte {
		t.Helper()
		x, err := ParamsDigest(ps)
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	if d(StringParam("a", "x"), StringParam("b", "y")) == d(StringParam("a", `x";b="y`)) {
		t.Fatal("N03: ayraç enjeksiyonu çakıştı")
	}
	// N04: nil ve boş aynı.
	var nilp []Param
	x1, _ := ParamsDigest(nilp)
	x2, _ := ParamsDigest([]Param{})
	if x1 != x2 {
		t.Fatal("N04: nil ve boş özet farklı")
	}
	// N05: "x" ≠ ["x"].
	if d(StringParam("k", "x")) == d(ListParam("k", "x")) {
		t.Fatal("N05: dize ile liste çakıştı")
	}
	// Sıra bağımsız.
	if d(StringParam("a", "1"), StringParam("b", "2")) != d(StringParam("b", "2"), StringParam("a", "1")) {
		t.Fatal("özet giriş sırasına bağlı")
	}
	// Boş liste ≠ boş dize.
	if d(ListParam("k")) == d(StringParam("k", "")) {
		t.Fatal("boş liste ile boş dize çakıştı")
	}
}

// N06: sayı/bool/null/iç içe parametreler malformed_params.
func TestN06_ParamsFromMapRejectsNonStrings(t *testing.T) {
	cases := map[string]map[string]any{
		"number": {"a": float64(1)},
		"int":    {"a": 1},
		"bool":   {"a": true},
		"null":   {"a": nil},
		"nested": {"a": map[string]any{"b": "c"}},
		"mixed":  {"a": []any{"x", float64(2)}},
		"listnl": {"a": []any{nil}},
	}
	for name, m := range cases {
		_, err := ParamsFromMap(m)
		if ReasonOf(err) != ReasonMalformedParams {
			t.Errorf("%s: neden %q (%v)", name, ReasonOf(err), err)
		}
	}
	ps, err := ParamsFromMap(map[string]any{"b": "2", "a": []any{"x", "y"}, "c": []string{"z"}})
	if err != nil || len(ps) != 3 || ps[0].Key != "a" || !ps[0].IsList {
		t.Fatalf("geçerli harita: %v %v", ps, err)
	}
}

// N07: geçersiz UTF-8 / NUL imzalamadan önce ve doğrulamada reddedilir.
func TestN07_InvalidUTF8AndNUL(t *testing.T) {
	bad := []string{"a\x00b", "a\xffb", "\xc0\xaf"}
	for _, s := range bad {
		e := tEnv()
		e.Params = []Param{StringParam("k", s)}
		if _, err := SignV2(tKey("cmdA"), tDevice, e); ReasonOf(err) != ReasonMalformedParams {
			t.Errorf("param %q imzalandı: %v", s, err)
		}
		e.Params = []Param{ListParam("k", "ok", s)}
		if _, err := SignV2(tKey("cmdA"), tDevice, e); ReasonOf(err) != ReasonMalformedParams {
			t.Errorf("liste öğesi %q imzalandı: %v", s, err)
		}
		e = tEnv()
		e.CorrelationID = s
		if _, err := SignV2(tKey("cmdA"), tDevice, e); err == nil {
			t.Errorf("correlation_id %q imzalandı", s)
		}
	}
	// Doğrulamada: geçerli imzalı zarfın params'ı sonradan bozulur.
	e := tSigned(t)
	e.Params = []Param{StringParam("reason", "ransom\x00ware")}
	_, err := tVerify(e, tDevice, tNow(), "cmdA")
	wantReason(t, err, ReasonMalformedParams)
}

// N08: alan-ayırma — başka bir alanın baytları v2 zarfı/bildirimi olarak sunulamaz.
func TestN08_DomainSeparation(t *testing.T) {
	e := tSigned(t)
	msg, _ := CanonicalV2(tDevice, e)
	if _, err := ParseStatement(msg); ReasonOf(err) != ReasonMalformedStatement {
		t.Fatalf("zarf iletisi bildirim olarak ayrıştı: %v", err)
	}
	pe, _ := EncodeParams(e.Params)
	if _, err := ParseCanonicalV2(pe); err == nil {
		t.Fatal("params baytları zarf olarak ayrıştı")
	}
	st := tGenesis(t)
	sm, _ := CanonicalStatement(st)
	if _, err := ParseCanonicalV2(sm); err == nil {
		t.Fatal("bildirim baytları zarf olarak ayrıştı")
	}
	if _, err := ParseParams(msg); err == nil {
		t.Fatal("zarf baytları params olarak ayrıştı")
	}
	// v1 kanonik baytları v2 ayrıştırıcısında anlamsızdır.
	v1 := CanonicalBytes(e.CommandID, tDevice, e.Type, e.RequestedBy, nil, e.Nonce, e.IssuedAtNS, e.ExpiresAtNS)
	if _, err := ParseCanonicalV2(v1); err == nil {
		t.Fatal("v1 baytları v2 olarak ayrıştı")
	}
	// Bir bildirim imzası zarf imzası olarak sunulursa doğrulanmaz.
	root := tKey("root1")
	sig := ed25519.Sign(root, sm)
	forged := e
	forged.Signature = sig
	forged.KeyID = KeyID(tPub("cmdA"))
	_, err := tVerify(forged, tDevice, tNow(), "cmdA")
	wantReason(t, err, ReasonBadSignature)
	// Sürüm-1 imzası (v1 baytları üzerinden) v2 olarak sunulursa doğrulanmaz.
	forged.Signature = ed25519.Sign(tKey("cmdA"), v1)
	_, err = tVerify(forged, tDevice, tNow(), "cmdA")
	wantReason(t, err, ReasonBadSignature)
}

// N09: key_id değişirse imza doğrulanmaz.
func TestN09_KeyIDAltered(t *testing.T) {
	e := tSigned(t)
	e.KeyID = KeyID(tPub("cmdB"))
	_, err := tVerify(e, tDevice, tNow(), "cmdA", "cmdB")
	wantReason(t, err, ReasonBadSignature)
	// Bilinmeyen anahtar kimliği: geçici unknown_key.
	e.KeyID = strings.Repeat("0", 32)
	_, err = tVerify(e, tDevice, tNow(), "cmdA")
	wantReason(t, err, ReasonUnknownKey)
	if !ReasonOf(err).Transient() {
		t.Fatal("unknown_key geçici olmalı")
	}
}

// N10: imzalı her alanda tek değişiklik → bad_signature.
func TestN10_EveryFieldIsCovered(t *testing.T) {
	e := tSigned(t)
	keys := []string{"cmdA", "cmdB"}
	mut := map[string]func(*Envelope, *string){
		"key_id":         func(x *Envelope, _ *string) { x.KeyID = KeyID(tPub("cmdB")) },
		"command_id":     func(x *Envelope, _ *string) { x.CommandID = "a1b2c3d4-e5f6-4a07-98a9-b0c1d2e3f4a6" },
		"device_id":      func(_ *Envelope, d *string) { *d = tDevice2 },
		"tenant_id":      func(x *Envelope, _ *string) { x.TenantID = "acmf" },
		"type":           func(x *Envelope, _ *string) { x.Type = TypeWipe },
		"requested_by":   func(x *Envelope, _ *string) { x.RequestedBy += "x" },
		"approved_by":    func(x *Envelope, _ *string) { x.ApprovedBy = "admin:other" },
		"correlation_id": func(x *Envelope, _ *string) { x.CorrelationID = "req-0002" },
		"sequence":       func(x *Envelope, _ *string) { x.Sequence++ },
		"nonce":          func(x *Envelope, _ *string) { x.Nonce = "00112233445566778899aabbccddeef0" },
		"issued_at":      func(x *Envelope, _ *string) { x.IssuedAtNS++ },
		"expires_at":     func(x *Envelope, _ *string) { x.ExpiresAtNS++ },
		"params_value": func(x *Envelope, _ *string) {
			x.Params = []Param{StringParam("reason", "ransomwarf"), ListParam("paths", "a", "b")}
		},
		"params_key": func(x *Envelope, _ *string) {
			x.Params = []Param{StringParam("reasoo", "ransomware"), ListParam("paths", "a", "b")}
		},
		"params_extra": func(x *Envelope, _ *string) {
			x.Params = append(append([]Param(nil), x.Params...), StringParam("z", "1"))
		},
	}
	for name, f := range mut {
		x, dev := e, tDevice
		f(&x, &dev)
		_, err := tVerify(x, dev, tNow(), keys...)
		if ReasonOf(err) != ReasonBadSignature {
			t.Errorf("%s: neden %q, beklenen bad_signature (%v)", name, ReasonOf(err), err)
		}
	}
	// Etki alanı etiketi: tek bit bozulursa ayrıştırma reddeder.
	msg, _ := CanonicalV2(tDevice, e)
	msg[5] ^= 0x01
	if _, err := ParseCanonicalV2(msg); err == nil {
		t.Fatal("bozuk etki alanı etiketi ayrıştı")
	}
}

// N11: imza/anahtar boyutları ve boş anahtar kümesi panik atmaz.
func TestN11_SizesAndEmptyKeySet(t *testing.T) {
	e := tSigned(t)
	if _, err := VerifyV2(e, VerifyInput{DeviceID: tDevice, Now: tNow()}); ReasonOf(err) != ReasonUnknownKey {
		t.Fatalf("boş küme: %v", err)
	}
	short := e
	short.Signature = e.Signature[:63]
	_, err := tVerify(short, tDevice, tNow(), "cmdA")
	wantReason(t, err, ReasonMalformedEnvelope)
	short.Signature = nil
	_, err = tVerify(short, tDevice, tNow(), "cmdA")
	wantReason(t, err, ReasonMalformedEnvelope)
	// Açık anahtar boyutu ≠ 32: o girdi yok sayılır → unknown_key.
	bad := tCmdKeys("cmdA")
	bad[0].Pub = bad[0].Pub[:31]
	_, err = VerifyV2(e, VerifyInput{DeviceID: tDevice, Keys: bad, Now: tNow()})
	wantReason(t, err, ReasonUnknownKey)
	if VerifySignature(tPub("cmdA")[:5], []byte("x"), e.Signature) {
		t.Fatal("kısa anahtar doğruladı")
	}
	if KeyID(tPub("cmdA")[:5]) != "" {
		t.Fatal("kısa anahtar için key_id boş olmalı")
	}
	if _, err := SignV2(ed25519.PrivateKey{1}, tDevice, tEnv()); err == nil {
		t.Fatal("kısa özel anahtar imzaladı")
	}
	// Kök rolündeki anahtar komut doğrulayamaz.
	rootAsCmd := tCmdKeys("cmdA")
	rootAsCmd[0].Role = KeyRoleRoot
	_, err = VerifyV2(e, VerifyInput{DeviceID: tDevice, Keys: rootAsCmd, Now: tNow()})
	wantReason(t, err, ReasonUnknownKey)
}

// N12: sunucu→JSONB→proto(structpb)→ajan yeniden kurulumunda özet değişmez.
func TestN12_DigestSurvivesJSONAndStructpb(t *testing.T) {
	m := map[string]any{
		"unicode": "çğış-日本語-😀", "long": strings.Repeat("ü", 100000),
		"list": []string{"b", "a", "", "ü"}, "empty": "",
	}
	for i := 0; i < 28; i++ {
		m["k_"+string(rune('a'+i%26))+string(rune('a'+i/26))] = "v"
	}
	if len(m) != 32 {
		t.Fatalf("32 anahtar bekleniyordu: %d", len(m))
	}
	orig, err := ParamsFromMap(m)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := ParamsDigest(orig)

	raw, _ := json.Marshal(m) // JSONB'ye gidiş
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	st, err := structpb.NewStruct(back) // proto
	if err != nil {
		t.Fatal(err)
	}
	wire, err := ParamsFromMap(st.AsMap()) // ajan
	if err != nil {
		t.Fatal(err)
	}
	got, _ := ParamsDigest(wire)
	if got != want {
		t.Fatal("özet JSON/structpb yolculuğunda değişti")
	}
}

// N13: envelope_version 0/1/3 → unsupported_version.
func TestN13_UnsupportedVersion(t *testing.T) {
	for _, v := range []uint32{0, 1, 3, 255} {
		e := tSigned(t)
		e.Version = v
		_, err := tVerify(e, tDevice, tNow(), "cmdA")
		wantReason(t, err, ReasonUnsupportedVersion)
	}
}

// N14: ömür sınırları.
func TestN14_Lifetime(t *testing.T) {
	sign := func(mod func(*Envelope)) error {
		e := tEnv()
		mod(&e)
		_, err := SignV2(tKey("cmdA"), tDevice, e)
		return err
	}
	wantReason(t, sign(func(e *Envelope) { e.ExpiresAtNS = e.IssuedAtNS }), ReasonBadLifetime)
	wantReason(t, sign(func(e *Envelope) { e.ExpiresAtNS = e.IssuedAtNS - 1 }), ReasonBadLifetime)
	wantReason(t, sign(func(e *Envelope) { e.ExpiresAtNS = e.IssuedAtNS + int64(MaxLifetime) + 1 }), ReasonBadLifetime)
	wantReason(t, sign(func(e *Envelope) { e.IssuedAtNS = 0 }), ReasonBadLifetime)
	if err := sign(func(e *Envelope) { e.ExpiresAtNS = e.IssuedAtNS + int64(MaxLifetime) }); err != nil {
		t.Fatalf("tam 31 gün geçerli olmalı: %v", err)
	}
	// Çok ileri issued: geçici not_yet_valid.
	e := tEnv()
	e.IssuedAtNS = tBase + int64(30*24*time.Hour)
	e.ExpiresAtNS = e.IssuedAtNS + int64(time.Hour)
	se, err := SignV2(tKey("cmdA"), tDevice, e)
	if err != nil {
		t.Fatal(err)
	}
	keys := tCmdKeys("cmdA")
	keys[0].NotAfterNS = tBase + int64(60*24*time.Hour)
	_, err = VerifyV2(se, VerifyInput{DeviceID: tDevice, Keys: keys, Now: tNow()})
	wantReason(t, err, ReasonNotYetValid)
	// 2 dk tolerans: now+2dk içindeki issued kabul, sonrası değil.
	e2 := tEnv()
	e2.IssuedAtNS = tNow().UnixNano() + int64(ClockSkew)
	e2.ExpiresAtNS = e2.IssuedAtNS + int64(time.Hour)
	s2, _ := SignV2(tKey("cmdA"), tDevice, e2)
	if _, err := tVerify(s2, tDevice, tNow(), "cmdA"); err != nil {
		t.Fatalf("skew sınırı kabul edilmeli: %v", err)
	}
	e2.IssuedAtNS++
	e2.ExpiresAtNS++
	s3, _ := SignV2(tKey("cmdA"), tDevice, e2)
	_, err = tVerify(s3, tDevice, tNow(), "cmdA")
	wantReason(t, err, ReasonNotYetValid)
}

func TestTimeChecks(t *testing.T) {
	e := tSigned(t)
	_, err := tVerify(e, tDevice, time.Time{}, "cmdA")
	wantReason(t, err, ReasonClockUnsynced)
	if !ReasonOf(err).Transient() {
		t.Fatal("clock_unsynced geçici olmalı")
	}
	_, err = tVerify(e, tDevice, time.Unix(0, e.ExpiresAtNS+1), "cmdA")
	wantReason(t, err, ReasonExpired)
	if ReasonOf(err).Transient() {
		t.Fatal("expired kalıcı olmalı")
	}
	if _, err := tVerify(e, tDevice, time.Unix(0, e.ExpiresAtNS), "cmdA"); err != nil {
		t.Fatalf("tam bitiş anı geçerli: %v", err)
	}
}

// N136: her imzalı dizge için sınır/karakter kümesi (imzalamadan ÖNCE ve doğrulamada).
func TestN136_FieldLimits(t *testing.T) {
	type tc struct {
		name string
		mod  func(*Envelope)
		want Reason
	}
	long := func(n int) string { return strings.Repeat("a", n) }
	cases := []tc{
		{"correlation 129", func(e *Envelope) { e.CorrelationID = long(129) }, ReasonMalformedEnvelope},
		{"correlation NUL", func(e *Envelope) { e.CorrelationID = "a\x00" }, ReasonMalformedEnvelope},
		{"correlation space", func(e *Envelope) { e.CorrelationID = "a b" }, ReasonMalformedEnvelope},
		{"correlation utf8", func(e *Envelope) { e.CorrelationID = "ü" }, ReasonMalformedEnvelope},
		{"correlation invalid utf8", func(e *Envelope) { e.CorrelationID = "\xff" }, ReasonMalformedEnvelope},
		{"tenant 64", func(e *Envelope) { e.TenantID = long(64) }, ReasonMalformedEnvelope},
		{"tenant space", func(e *Envelope) { e.TenantID = "a b" }, ReasonMalformedEnvelope},
		{"requested_by empty", func(e *Envelope) { e.RequestedBy = "" }, ReasonMalformedEnvelope},
		{"requested_by 129", func(e *Envelope) { e.RequestedBy = long(129) }, ReasonMalformedEnvelope},
		{"requested_by 0x1f", func(e *Envelope) { e.RequestedBy = "a\x1fb" }, ReasonMalformedEnvelope},
		{"approved_by 129", func(e *Envelope) { e.ApprovedBy = long(129) }, ReasonMalformedEnvelope},
		{"approved_by == requested_by", func(e *Envelope) { e.ApprovedBy = e.RequestedBy }, ReasonMalformedEnvelope},
		{"command_id uppercase", func(e *Envelope) { e.CommandID = strings.ToUpper(e.CommandID) }, ReasonMalformedEnvelope},
		{"command_id braces", func(e *Envelope) { e.CommandID = "{" + e.CommandID + "}" }, ReasonMalformedEnvelope},
		{"command_id no hyphens", func(e *Envelope) { e.CommandID = strings.ReplaceAll(e.CommandID, "-", "") }, ReasonMalformedEnvelope},
		{"command_id v1 uuid", func(e *Envelope) { e.CommandID = "11111111-1111-1111-8111-111111111111" }, ReasonMalformedEnvelope},
		{"command_id bad variant", func(e *Envelope) { e.CommandID = "11111111-1111-4111-c111-111111111111" }, ReasonMalformedEnvelope},
		{"nonce uppercase", func(e *Envelope) { e.Nonce = strings.ToUpper(e.Nonce) }, ReasonMalformedEnvelope},
		{"nonce 31", func(e *Envelope) { e.Nonce = e.Nonce[:31] }, ReasonMalformedEnvelope},
		{"nonce 33", func(e *Envelope) { e.Nonce += "0" }, ReasonMalformedEnvelope},
		{"nonce non-hex", func(e *Envelope) { e.Nonce = strings.Repeat("g", 32) }, ReasonMalformedEnvelope},
		{"type unknown", func(e *Envelope) { e.Type = "REBOOT" }, ReasonUnknownType},
		{"type lowercase", func(e *Envelope) { e.Type = "quarantine" }, ReasonUnknownType},
		{"type padded", func(e *Envelope) { e.Type = " QUARANTINE" }, ReasonUnknownType},
		{"type empty", func(e *Envelope) { e.Type = "" }, ReasonUnknownType},
		{"params 33 keys", func(e *Envelope) {
			e.Params = nil
			for i := 0; i < 33; i++ {
				e.Params = append(e.Params, StringParam("k"+strings.Repeat("a", i/26)+string(rune('a'+i%26)), "v"))
			}
		}, ReasonMalformedParams},
		{"params key uppercase", func(e *Envelope) { e.Params = []Param{StringParam("Key", "v")} }, ReasonMalformedParams},
		{"params key empty", func(e *Envelope) { e.Params = []Param{StringParam("", "v")} }, ReasonMalformedParams},
		{"params key 65", func(e *Envelope) { e.Params = []Param{StringParam(long(65), "v")} }, ReasonMalformedParams},
		{"params dup key", func(e *Envelope) { e.Params = []Param{StringParam("a", "1"), StringParam("a", "2")} }, ReasonMalformedParams},
		{"params string 256KiB+1", func(e *Envelope) { e.Params = []Param{StringParam("a", long(MaxParamStringBytes+1))} }, ReasonMalformedParams},
		{"params list 65", func(e *Envelope) { e.Params = []Param{ListParam("a", make([]string, 65)...)} }, ReasonMalformedParams},
		{"params total 512KiB+", func(e *Envelope) {
			e.Params = []Param{StringParam("a", long(MaxParamStringBytes)), StringParam("b", long(MaxParamStringBytes)), StringParam("c", "x")}
		}, ReasonMalformedParams},
		{"params list+value", func(e *Envelope) { e.Params = []Param{{Key: "a", Value: "x", IsList: true}} }, ReasonMalformedParams},
		{"params string+list", func(e *Envelope) { e.Params = []Param{{Key: "a", Value: "x", List: []string{"y"}}} }, ReasonMalformedParams},
	}
	for _, c := range cases {
		e := tEnv()
		c.mod(&e)
		_, err := SignV2(tKey("cmdA"), tDevice, e)
		if ReasonOf(err) != c.want {
			t.Errorf("%s: imzalama nedeni %q (%v), beklenen %q", c.name, ReasonOf(err), err, c.want)
		}
		// Doğrulamada: geçerli imzalı zarfa aynı bozma uygulanır.
		ok := tSigned(t)
		keepSig := ok.Signature
		c.mod(&ok)
		ok.Signature = keepSig
		ok.KeyID = KeyID(tPub("cmdA"))
		ok.Version = EnvelopeVersion2
		_, err = tVerify(ok, tDevice, tNow(), "cmdA")
		if ReasonOf(err) != c.want {
			t.Errorf("%s: doğrulama nedeni %q (%v), beklenen %q", c.name, ReasonOf(err), err, c.want)
		}
	}
	// Anahtar kimliği: 64-bit (16 hex) ve büyük harf reddedilir.
	for name, id := range map[string]string{"64-bit": KeyID(tPub("cmdA"))[:16], "uppercase": strings.ToUpper(KeyID(tPub("cmdA"))), "empty": ""} {
		e := tSigned(t)
		e.KeyID = id
		_, err := tVerify(e, tDevice, tNow(), "cmdA")
		if ReasonOf(err) != ReasonMalformedEnvelope {
			t.Errorf("key_id %s: neden %q", name, ReasonOf(err))
		}
	}
	// Cihaz kimliği: karışık harf ve sınırlar.
	for name, id := range map[string]string{
		"mixed": "0B1c2d3e-4f50-4a61-8b72-93a4b5c6d7e8", "empty": "", "65": strings.Repeat("a", 65), "space": "a b",
	} {
		if _, err := CanonicalV2(id, tEnv()); ReasonOf(err) != ReasonBadDeviceID {
			t.Errorf("device_id %s: imzalama nedeni %q", name, ReasonOf(err))
		}
		_, err := tVerify(tSigned(t), id, tNow(), "cmdA")
		if ReasonOf(err) != ReasonBadDeviceID {
			t.Errorf("device_id %s: doğrulama nedeni %q", name, ReasonOf(err))
		}
	}
	// Sınır DEĞERLERİ geçerli olmalı.
	e := tEnv()
	e.CorrelationID = strings.Repeat("a", 128)
	e.RequestedBy = strings.Repeat("r", 128)
	e.ApprovedBy = strings.Repeat("p", 128)
	e.TenantID = strings.Repeat("t", 63)
	if _, err := SignV2(tKey("cmdA"), strings.Repeat("d", 64), e); err != nil {
		t.Fatalf("sınır değerleri geçerli olmalı: %v", err)
	}
}

func TestParamsLimitsAtBoundary(t *testing.T) {
	ps := []Param{StringParam("a", strings.Repeat("a", MaxParamStringBytes))}
	if err := ValidateParams(ps); err != nil {
		t.Fatalf("256 KiB geçerli olmalı: %v", err)
	}
	var many []Param
	for i := 0; i < MaxParamKeys; i++ {
		many = append(many, StringParam("k"+string(rune('a'+i%26))+string(rune('a'+i/26)), "v"))
	}
	if err := ValidateParams(many); err != nil {
		t.Fatalf("32 anahtar geçerli olmalı: %v", err)
	}
	if err := ValidateParams([]Param{ListParam("a", make([]string, 64)...)}); err != nil {
		t.Fatalf("64 öğe geçerli olmalı: %v", err)
	}
}

// Katı ayrıştırıcı: artık bayt, kısaltma, sırasız/yinelenen params, aşırı uzunluk.
func TestStrictParsers(t *testing.T) {
	msg, _ := CanonicalV2(tDevice, tSigned(t))
	if _, err := ParseCanonicalV2(append(append([]byte(nil), msg...), 0)); err == nil {
		t.Fatal("artık bayt kabul edildi")
	}
	for i := 0; i < len(msg); i++ {
		if _, err := ParseCanonicalV2(msg[:i]); err == nil {
			t.Fatalf("kısaltılmış girdi (%d bayt) kabul edildi", i)
		}
	}
	// Tek alanın uzunluk öneki şişirilirse bellek ayırmadan reddedilir.
	big := append([]byte(nil), msg...)
	big[4+19+3] = 0xff // key_id uzunluğunun son baytı
	if _, err := ParseCanonicalV2(big); err == nil {
		t.Fatal("şişirilmiş uzunluk kabul edildi")
	}

	enc, _ := EncodeParams([]Param{StringParam("a", "1"), StringParam("b", "2")})
	if _, err := ParseParams(append(enc[:len(enc):len(enc)], 0)); err == nil {
		t.Fatal("params artık baytı kabul edildi")
	}
	for i := 0; i < len(enc); i++ {
		if _, err := ParseParams(enc[:i]); err == nil {
			t.Fatalf("kısaltılmış params (%d) kabul edildi", i)
		}
	}
	mk := func(keys ...string) []byte {
		b := appendLP(nil, DomainParamsV2)
		b = appendU32(b, uint32(len(keys)))
		for _, k := range keys {
			b = appendLP(b, k)
			b = append(b, paramTagString)
			b = appendLP(b, "v")
		}
		return b
	}
	if _, err := ParseParams(mk("a", "b")); err != nil {
		t.Fatalf("sıralı kümeyi reddetti: %v", err)
	}
	if _, err := ParseParams(mk("b", "a")); err == nil {
		t.Fatal("sırasız params kabul edildi")
	}
	if _, err := ParseParams(mk("a", "a")); err == nil {
		t.Fatal("yinelenen params kabul edildi")
	}
	if _, err := ParseParams(mk("A")); err == nil {
		t.Fatal("büyük harfli anahtar kabul edildi")
	}
	bad := mk("a")
	bad[len(bad)-6] = 0x09 // bilinmeyen tür etiketi
	if _, err := ParseParams(bad); err == nil {
		t.Fatal("bilinmeyen tür etiketi kabul edildi")
	}
	rt, err := ParseParams(enc)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := EncodeParams(rt); !bytes.Equal(again, enc) {
		t.Fatal("params gidiş-dönüş bayt-bayt aynı değil")
	}
}

// Ek imzalar: N149 (ortak imza, bilinmeyen ek yok sayılır), biçim kuralları.
func TestExtraSignatures(t *testing.T) {
	e := tSigned(t)
	co, err := CoSignV2(tKey("cmdB"), tDevice, e)
	if err != nil {
		t.Fatal(err)
	}
	e.ExtraSignatures = []Signature{co}
	for _, trusted := range [][]string{{"cmdA"}, {"cmdB"}, {"cmdA", "cmdB"}} {
		v, err := tVerify(e, tDevice, tNow(), trusted...)
		if err != nil {
			t.Fatalf("%v güvenen ajan reddetti: %v", trusted, err)
		}
		if len(v.KeyIDs) != len(trusted) {
			t.Errorf("%v: geçerli imza sayısı %d", trusted, len(v.KeyIDs))
		}
	}
	// Hiçbirine güvenmeyen ajan: unknown_key.
	_, err = tVerify(e, tDevice, tNow(), "cmdC")
	wantReason(t, err, ReasonUnknownKey)
	// Bilinmeyen ek anahtar görmezden gelinir.
	evil, _ := CoSignV2(tKey("evil"), tDevice, e)
	e.ExtraSignatures = []Signature{evil}
	if _, err := tVerify(e, tDevice, tNow(), "cmdA"); err != nil {
		t.Fatalf("bilinmeyen ek imza engel olmamalı: %v", err)
	}
	// Biçim: kısa imza, yinelenen anahtar, birincil ile aynı anahtar, fazla sayıda.
	e.ExtraSignatures = []Signature{{KeyID: co.KeyID, Sig: co.Sig[:10]}}
	_, err = tVerify(e, tDevice, tNow(), "cmdA")
	wantReason(t, err, ReasonMalformedEnvelope)
	e.ExtraSignatures = []Signature{co, co}
	_, err = tVerify(e, tDevice, tNow(), "cmdA")
	wantReason(t, err, ReasonMalformedEnvelope)
	e.ExtraSignatures = []Signature{{KeyID: e.KeyID, Sig: e.Signature}}
	_, err = tVerify(e, tDevice, tNow(), "cmdA")
	wantReason(t, err, ReasonMalformedEnvelope)
	e.ExtraSignatures = make([]Signature, MaxExtraSignatures+1)
	_, err = tVerify(e, tDevice, tNow(), "cmdA")
	wantReason(t, err, ReasonMalformedEnvelope)
	// Ek imza, KENDİ key_id'sinin yerleştirildiği iletiyi imzalar: birincilin imzası olamaz.
	e = tSigned(t)
	e.ExtraSignatures = []Signature{{KeyID: KeyID(tPub("cmdB")), Sig: e.Signature}}
	_, err = tVerify(e, tDevice, tNow(), "cmdB")
	wantReason(t, err, ReasonBadSignature)
}

// N111 (zarf yarısı): anahtar penceresi issued_at anına göre değerlendirilir.
func TestKeyWindowUsesIssuedAt(t *testing.T) {
	e := tSigned(t) // issued = tBase
	k := tCmdKeys("cmdA")
	// issued < not_before
	k[0].NotBeforeNS = tBase + 1
	_, err := VerifyV2(e, VerifyInput{DeviceID: tDevice, Keys: k, Now: tNow()})
	wantReason(t, err, ReasonKeyExpired)
	// issued > not_after (anahtar komuttan önce sona erdi)
	k = tCmdKeys("cmdA")
	k[0].NotAfterNS = tBase - 1
	_, err = VerifyV2(e, VerifyInput{DeviceID: tDevice, Keys: k, Now: tNow()})
	wantReason(t, err, ReasonKeyExpired)
	// issued == not_after: kabul; ANCAK now > not_after olsa bile kabul (çevrimdışı teslim).
	k = tCmdKeys("cmdA")
	k[0].NotAfterNS = tBase
	if _, err := VerifyV2(e, VerifyInput{DeviceID: tDevice, Keys: k, Now: tNow()}); err != nil {
		t.Fatalf("issued==not_after kabul edilmeli (anahtar sona ermeden imzalanmış): %v", err)
	}
	// not_after==0 komut anahtarı için geçersiz (fail-closed).
	k = tCmdKeys("cmdA")
	k[0].NotAfterNS = 0
	_, err = VerifyV2(e, VerifyInput{DeviceID: tDevice, Keys: k, Now: tNow()})
	wantReason(t, err, ReasonKeyExpired)
}

func TestSignV2ReplacesAndSetsFields(t *testing.T) {
	e := tEnv()
	e.Version = 1
	e.KeyID = "junk"
	e.Signature = []byte{1}
	e.ExtraSignatures = []Signature{{}}
	s, err := SignV2(tKey("cmdA"), tDevice, e)
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != 2 || s.KeyID != KeyID(tPub("cmdA")) || len(s.ExtraSignatures) != 0 || len(s.Signature) != 64 {
		t.Fatalf("SignV2 alanları: %+v", s)
	}
}

func TestSequenceEncodingU64(t *testing.T) {
	// U64: 8 bayt büyük-endian; 2^32 üzeri ve azami değer.
	for _, seq := range []uint64{0, 1, 1 << 32, 0x0102030405060708, ^uint64(0)} {
		e := tEnv()
		e.Sequence = seq
		msg, err := CanonicalV2(tDevice, e)
		if err != nil {
			t.Fatal(err)
		}
		f, err := ParseCanonicalV2(msg)
		if err != nil || f.Sequence != seq {
			t.Fatalf("sequence %d gidiş-dönüş: %d %v", seq, f.Sequence, err)
		}
	}
	e := tEnv()
	e.Sequence = 0x0102030405060708
	msg, _ := CanonicalV2(tDevice, e)
	if !bytes.Contains(msg, []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatal("sequence 8 bayt büyük-endian olarak yazılmadı")
	}
}

func TestTransientClassification(t *testing.T) {
	for _, r := range []Reason{ReasonUnknownKey, ReasonClockUnsynced, ReasonNotYetValid} {
		if !r.Transient() {
			t.Errorf("%s geçici olmalı", r)
		}
	}
	for _, r := range []Reason{ReasonBadSignature, ReasonExpired, ReasonKeyExpired, ReasonMalformedEnvelope, ReasonUnknownType, ReasonBadLifetime, ReasonUnsupportedVersion} {
		if r.Transient() {
			t.Errorf("%s kalıcı olmalı", r)
		}
	}
}

func TestEveryKnownTypeSignsAndVerifies(t *testing.T) {
	for _, s := range All() {
		e := tEnv()
		e.Type = s.Name
		if s.DualControl {
			e.ApprovedBy = "admin:approver"
		}
		se, err := SignV2(tKey("cmdA"), tDevice, e)
		if err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
		if _, err := tVerify(se, tDevice, tNow(), "cmdA"); err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
	}
	if RequiredSignatures(TypeWipe) != 1 {
		t.Fatal("W2'de gereken imza sayısı 1 olmalı")
	}
}

func TestFamily(t *testing.T) {
	if Family(TypeQuarantine) != FamilyIsolation || Family(TypeUnquarantine) != FamilyIsolation {
		t.Fatal("QUARANTINE ve UNQUARANTINE aynı ailede olmalı")
	}
	seen := map[string]string{}
	for _, s := range All() {
		f := Family(s.Name)
		if f == "" {
			t.Errorf("%s ailesiz", s.Name)
		}
		if prev, dup := seen[f]; dup && f != FamilyIsolation {
			t.Errorf("%s ve %s aynı ailede (%s)", prev, s.Name, f)
		}
		seen[f] = s.Name
	}
	if Family("") != "" || Family("quarantine") != "" || Family("REBOOT") != "" {
		t.Fatal("bilinmeyen tip ailesiz (\"\") olmalı")
	}
}
