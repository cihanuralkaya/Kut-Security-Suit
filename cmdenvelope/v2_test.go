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

// tCmdKeys: verilen adlar için [base-1h, base+90d] penceresinde komut anahtarları.
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
		CommandID: "a1b2c3d4-e5f6-4a07-98a9-b0c1d2e3f4a5", TenantID: "acme", Type: TypeQuarantine,
		RequestedBy: "admin:9f8e7d6c-5b4a-4392-8180-706f5e4d3c2b", CorrelationID: "req-0001",
		Sequence: 7, Nonce: "00112233445566778899aabbccddeeff",
		IssuedAtNS: tBase, ExpiresAtNS: tBase + int64(7*24*time.Hour),
		Params: []Param{StringParam("reason", "ransomware"), ListParam("paths", "a", "b")},
	}
}

func tSigned(t *testing.T) DSSE {
	t.Helper()
	d, err := SignV2(tKey("cmdA"), tDevice, tEnv())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// tVerify, tEnv() params'ı ile doğrular.
func tVerify(d DSSE, dev string, now time.Time, keys ...string) (Verified, error) {
	return VerifyV2(d, tEnv().Params, VerifyInput{DeviceID: dev, Keys: tCmdKeys(keys...), Now: now})
}

// tPayloadMut, imzalı zarfın gövdesini Fields üzerinden değiştirir ve ESKİ imzaları korur.
func tPayloadMut(t *testing.T, d DSSE, mod func(*Fields)) DSSE {
	t.Helper()
	f, err := ParseCanonicalV2(d.Payload)
	if err != nil {
		t.Fatal(err)
	}
	mod(&f)
	out := d
	out.Payload = f.EncodeUnvalidated()
	return out
}

// tCrafted, mod uygulanmış gövdeyi cmdA ile GEÇERLİ imzalar (biçimsiz gövdenin geçerli imzayla
// bile reddedildiğini sınamak için).
func tCrafted(t *testing.T, mod func(*Fields)) DSSE {
	t.Helper()
	f, err := tEnv().Fields(tDevice)
	if err != nil {
		t.Fatal(err)
	}
	mod(&f)
	body := f.EncodeUnvalidated()
	sig, err := SignDSSE(tKey("cmdA"), PayloadTypeCommand, body)
	if err != nil {
		t.Fatal(err)
	}
	return DSSE{PayloadType: PayloadTypeCommand, Payload: body, Signatures: []DSSESignature{sig}}
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

func mustSig(t *testing.T, key, payloadType string, payload []byte) DSSESignature {
	t.Helper()
	s, err := SignDSSE(tKey(key), payloadType, payload)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignVerifyRoundTrip(t *testing.T) {
	d := tSigned(t)
	v, err := tVerify(d, tDevice, tNow(), "cmdA")
	if err != nil {
		t.Fatal(err)
	}
	if len(v.KeyIDs) != 1 || v.KeyIDs[0] != KeyID(tPub("cmdA")) {
		t.Fatalf("anahtar kimlikleri: %v", v.KeyIDs)
	}
	if v.Digest != sha256.Sum256(PAE(PayloadTypeCommand, d.Payload)) {
		t.Fatal("envelope_digest = sha256(PAE) değil")
	}
	if v.Fields.CommandID != tEnv().CommandID || v.Fields.DeviceID != tDevice || v.Fields.Sequence != 7 {
		t.Fatalf("doğrulanmış alanlar: %+v", v.Fields)
	}
	if len(KeyID(tPub("cmdA"))) != 32 {
		t.Fatal("keyid 128-bit hex değil")
	}
}

// Gövde düzeni: etiket ilk alan, key_id YOK, gövde tüm imzacılar için aynı.
func TestCanonicalV2_FixedLayout(t *testing.T) {
	d := tSigned(t)
	if !bytes.HasPrefix(d.Payload, append([]byte{0, 0, 0, 19}, "kut-cmd-envelope-v2"...)) {
		t.Fatalf("etiket öneki hatalı: %x", d.Payload[:24])
	}
	f, err := ParseCanonicalV2(d.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if f.Sequence != 7 || f.DeviceID != tDevice || f.TenantID != "acme" {
		t.Fatalf("ayrıştırma sonucu hatalı: %+v", f)
	}
	again, _ := f.Encode()
	if !bytes.Equal(again, d.Payload) {
		t.Fatal("Parse→Encode bayt-bayt aynı değil")
	}
	co, err := CoSign(tKey("cmdB"), d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(co.Payload, d.Payload) || len(co.Signatures) != 2 {
		t.Fatal("ek imza gövdeyi değiştirdi / imza eklenmedi")
	}
	if bytes.Contains(d.Payload, []byte(KeyID(tPub("cmdA")))) {
		t.Fatal("key_id gövdede bulunmamalı")
	}
}

// N02: 0x1f içeren requested_by reddedilir; bitişik alanlar arasında bayt kaydırma farklı bayt üretir.
func TestN02_LengthPrefixedFieldsDoNotAlias(t *testing.T) {
	e := tEnv()
	e.RequestedBy = "admin:x\x1fy"
	if _, err := SignV2(tKey("cmdA"), tDevice, e); err == nil {
		t.Fatal("0x1f içeren requested_by imzalanmamalı")
	}
	a, b := tEnv(), tEnv()
	a.RequestedBy, a.CorrelationID = "ab", "c"
	b.RequestedBy, b.CorrelationID = "a", "bc"
	ma, err1 := CanonicalV2(tDevice, a)
	mb, err2 := CanonicalV2(tDevice, b)
	if err1 != nil || err2 != nil || bytes.Equal(ma, mb) {
		t.Fatalf("bitişik alanlar arası bayt kaydırma aynı gövdeyi üretti (%v %v)", err1, err2)
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
	var nilp []Param
	x1, _ := ParamsDigest(nilp)
	x2, _ := ParamsDigest([]Param{})
	if x1 != x2 {
		t.Fatal("N04: nil ve boş özet farklı")
	}
	if d(StringParam("k", "x")) == d(ListParam("k", "x")) {
		t.Fatal("N05: dize ile liste çakıştı")
	}
	if d(StringParam("a", "1"), StringParam("b", "2")) != d(StringParam("b", "2"), StringParam("a", "1")) {
		t.Fatal("özet giriş sırasına bağlı")
	}
	if d(ListParam("k")) == d(StringParam("k", "")) {
		t.Fatal("boş liste ile boş dize çakıştı")
	}
}

// N06: sayı/bool/null/iç içe parametreler malformed_params.
func TestN06_ParamsFromMapRejectsNonStrings(t *testing.T) {
	cases := map[string]map[string]any{
		"number": {"a": float64(1)}, "int": {"a": 1}, "bool": {"a": true}, "null": {"a": nil},
		"nested": {"a": map[string]any{"b": "c"}}, "mixed": {"a": []any{"x", float64(2)}}, "listnl": {"a": []any{nil}},
	}
	for name, m := range cases {
		if _, err := ParamsFromMap(m); ReasonOf(err) != ReasonMalformedParams {
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
	for _, s := range []string{"a\x00b", "a\xffb", "\xc0\xaf"} {
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
	_, err := VerifyV2(tSigned(t), []Param{StringParam("reason", "ransom\x00ware")}, VerifyInput{DeviceID: tDevice, Keys: tCmdKeys("cmdA"), Now: tNow()})
	wantReason(t, err, ReasonMalformedParams)
}

// N08: alanlar-arası ayrım. Yük türü PAE'ye dahildir; başka nesne türü olarak sunulan imza geçmez.
func TestN08_DomainSeparation(t *testing.T) {
	d := tSigned(t)
	if _, err := ParseStatement(d.Payload); ReasonOf(err) != ReasonMalformedStatement {
		t.Fatalf("komut gövdesi bildirim olarak ayrıştı: %v", err)
	}
	st := tGenesis(t)
	sm, _ := CanonicalStatement(st)
	if _, err := ParseCanonicalV2(sm); err == nil {
		t.Fatal("bildirim gövdesi komut olarak ayrıştı")
	}
	pe, _ := EncodeParams(tEnv().Params)
	if _, err := ParseCanonicalV2(pe); err == nil {
		t.Fatal("params baytları zarf olarak ayrıştı")
	}
	if _, err := ParseParams(d.Payload); err == nil {
		t.Fatal("zarf baytları params olarak ayrıştı")
	}
	v1 := CanonicalBytes(tEnv().CommandID, tDevice, TypeQuarantine, "admin:x", nil, tEnv().Nonce, tBase, tBase+1)
	if _, err := ParseCanonicalV2(v1); err == nil {
		t.Fatal("v1 baytları v2 olarak ayrıştı")
	}
	if _, err := ParseStatementDSSE(d); ReasonOf(err) != ReasonBadPayloadType {
		t.Fatalf("komut zarfı bildirim olarak kabul edildi: %v", err)
	}
	sd, _ := st.DSSE()
	if _, err := VerifyV2(sd, nil, VerifyInput{DeviceID: tDevice, Keys: tCmdKeys("cmdA"), Now: tNow()}); ReasonOf(err) != ReasonBadPayloadType {
		t.Fatalf("bildirim zarfı komut olarak kabul edildi: %v", err)
	}
	// Başka yük türü altında atılmış (geçerli) imza, doğru türle sunulursa geçmez.
	other := mustSig(t, "cmdA", PayloadTypeTrust, d.Payload)
	forged := DSSE{PayloadType: PayloadTypeCommand, Payload: d.Payload, Signatures: []DSSESignature{other}}
	_, err := tVerify(forged, tDevice, tNow(), "cmdA")
	wantReason(t, err, ReasonBadSignature)
	// v1 baytları üzerindeki imza v2 olarak sunulursa geçmez.
	forged.Signatures = []DSSESignature{{KeyID: KeyID(tPub("cmdA")), Sig: ed25519.Sign(tKey("cmdA"), v1)}}
	_, err = tVerify(forged, tDevice, tNow(), "cmdA")
	wantReason(t, err, ReasonBadSignature)
}

// DSSE: PAE bayt kodlaması sabit; gövde PAE olmadan imzalanırsa reddedilir.
func TestDSSE_PAEPinnedAndRequired(t *testing.T) {
	got := PAE("application/vnd.kut.cmd.v2", []byte("hello"))
	if string(got) != "DSSEv1 26 application/vnd.kut.cmd.v2 5 hello" {
		t.Fatalf("PAE = %q", got)
	}
	// DSSE spesifikasyonundaki örnek.
	if spec := PAE("http://example.com/HelloWorld", []byte("hello world")); string(spec) != "DSSEv1 29 http://example.com/HelloWorld 11 hello world" {
		t.Fatalf("spesifikasyon örneği: %q", spec)
	}
	if string(PAE("t", nil)) != "DSSEv1 1 t 0 " {
		t.Fatalf("boş gövde: %q", PAE("t", nil))
	}
	if !strings.HasPrefix(string(PAE(strings.Repeat("x", 100), nil)), "DSSEv1 100 ") {
		t.Fatal("üç haneli uzunluk ondalık yazılmadı")
	}
	d := tSigned(t)
	raw := DSSE{PayloadType: d.PayloadType, Payload: d.Payload,
		Signatures: []DSSESignature{{KeyID: KeyID(tPub("cmdA")), Sig: ed25519.Sign(tKey("cmdA"), d.Payload)}}}
	_, err := tVerify(raw, tDevice, tNow(), "cmdA")
	wantReason(t, err, ReasonBadSignature)
	manual := DSSE{PayloadType: d.PayloadType, Payload: d.Payload,
		Signatures: []DSSESignature{{KeyID: KeyID(tPub("cmdA")), Sig: ed25519.Sign(tKey("cmdA"), PAE(d.PayloadType, d.Payload))}}}
	if _, err := tVerify(manual, tDevice, tNow(), "cmdA"); err != nil {
		t.Fatalf("elle PAE imzası reddedildi: %v", err)
	}
}

func TestDSSE_JSONStrict(t *testing.T) {
	d, _ := CoSign(tKey("cmdB"), tSigned(t))
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"payloadType":"application/vnd.kut.cmd.v2"`)) || !bytes.Contains(raw, []byte(`"keyid"`)) {
		t.Fatalf("DSSE JSON alan adları: %s", raw)
	}
	back, err := ParseDSSEJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if back.PayloadType != d.PayloadType || !bytes.Equal(back.Payload, d.Payload) || len(back.Signatures) != 2 || !bytes.Equal(back.Signatures[1].Sig, d.Signatures[1].Sig) {
		t.Fatal("JSON gidiş-dönüş eşit değil")
	}
	bad := map[string]string{
		"unknown field":   `{"payloadType":"t","payload":"AA==","signatures":[],"extra":1}`,
		"trailing data":   string(raw) + `{}`,
		"url-safe base64": `{"payloadType":"t","payload":"__8=","signatures":[]}`,
		"unpadded base64": `{"payloadType":"t","payload":"AA","signatures":[]}`,
		"not json":        `nope`,
		"empty":           ``,
		"too many sigs":   `{"payloadType":"t","payload":"AA==","signatures":[` + strings.TrimSuffix(strings.Repeat(`{"keyid":"k","sig":"AA=="},`, 9), ",") + `]}`,
		"oversize":        `{"payloadType":"t","payload":"` + strings.Repeat("A", MaxDSSEJSONBytes) + `","signatures":[]}`,
	}
	for name, in := range bad {
		if _, err := ParseDSSEJSON([]byte(in)); err == nil {
			t.Errorf("%s: kabul edildi", name)
		}
	}
	for name, mod := range map[string]func(*DSSE){
		"no signatures": func(x *DSSE) { x.Signatures = nil },
		"nine sigs": func(x *DSSE) {
			x.Signatures = nil
			for i := 0; i < 9; i++ {
				x.Signatures = append(x.Signatures, d.Signatures[0])
			}
		},
		"empty payload": func(x *DSSE) { x.Payload = nil },
		"huge payload":  func(x *DSSE) { x.Payload = make([]byte, MaxDSSEPayloadBytes+1) },
		"short sig":     func(x *DSSE) { x.Signatures = []DSSESignature{{KeyID: d.Signatures[0].KeyID, Sig: []byte{1}}} },
		"uppercase keyid": func(x *DSSE) {
			x.Signatures = []DSSESignature{{KeyID: strings.ToUpper(d.Signatures[0].KeyID), Sig: d.Signatures[0].Sig}}
		},
	} {
		x := d
		mod(&x)
		if _, err := VerifyV2(x, tEnv().Params, VerifyInput{DeviceID: tDevice, Keys: tCmdKeys("cmdA"), Now: tNow()}); ReasonOf(err) != ReasonMalformedEnvelope {
			t.Errorf("%s: neden %q", name, ReasonOf(err))
		}
	}
}

// N09: keyid ipucu yanlış anahtarı gösterirse imza doğrulanmaz; bilinmeyen keyid geçici.
func TestN09_KeyIDHint(t *testing.T) {
	d := tSigned(t)
	d.Signatures = []DSSESignature{{KeyID: KeyID(tPub("cmdB")), Sig: d.Signatures[0].Sig}}
	_, err := tVerify(d, tDevice, tNow(), "cmdA", "cmdB")
	wantReason(t, err, ReasonBadSignature)
	d.Signatures[0].KeyID = strings.Repeat("0", 32)
	_, err = tVerify(d, tDevice, tNow(), "cmdA")
	wantReason(t, err, ReasonUnknownKey)
	if !ReasonOf(err).Transient() {
		t.Fatal("unknown_key geçici olmalı")
	}
}

// N10: imzalı her alanda tek değişiklik → bad_signature (gövde değişir, imza eskisi).
func TestN10_EveryFieldIsCovered(t *testing.T) {
	d := tSigned(t)
	mut := map[string]func(*Fields){
		"command_id":     func(f *Fields) { f.CommandID = "a1b2c3d4-e5f6-4a07-98a9-b0c1d2e3f4a6" },
		"tenant_id":      func(f *Fields) { f.TenantID = "acmf" },
		"type":           func(f *Fields) { f.Type = TypeWipe },
		"requested_by":   func(f *Fields) { f.RequestedBy += "x" },
		"approved_by":    func(f *Fields) { f.ApprovedBy = "admin:other" },
		"correlation_id": func(f *Fields) { f.CorrelationID = "req-0002" },
		"sequence":       func(f *Fields) { f.Sequence++ },
		"nonce":          func(f *Fields) { f.Nonce = "00112233445566778899aabbccddeef0" },
		"issued_at":      func(f *Fields) { f.IssuedAtNS++ },
		"expires_at":     func(f *Fields) { f.ExpiresAtNS++ },
		"params_digest":  func(f *Fields) { f.ParamsDigest[0] ^= 1 },
	}
	for name, m := range mut {
		x := tPayloadMut(t, d, m)
		if _, err := tVerify(x, tDevice, tNow(), "cmdA"); ReasonOf(err) != ReasonBadSignature {
			t.Errorf("%s: neden %q, beklenen bad_signature (%v)", name, ReasonOf(err), err)
		}
	}
	// Gövdedeki cihaz değişirse: doğrulayanın kimliğine eşit olmadığı için wrong_device.
	x := tPayloadMut(t, d, func(f *Fields) { f.DeviceID = tDevice2 })
	_, err := tVerify(x, tDevice, tNow(), "cmdA")
	wantReason(t, err, ReasonWrongDevice)
	// Telde taşınan params değişirse özet uyuşmaz.
	for name, ps := range map[string][]Param{
		"params_value": {StringParam("reason", "ransomwarf"), ListParam("paths", "a", "b")},
		"params_key":   {StringParam("reasoo", "ransomware"), ListParam("paths", "a", "b")},
		"params_extra": {StringParam("reason", "ransomware"), ListParam("paths", "a", "b"), StringParam("z", "1")},
		"params_none":  nil,
	} {
		_, err := VerifyV2(d, ps, VerifyInput{DeviceID: tDevice, Keys: tCmdKeys("cmdA"), Now: tNow()})
		if ReasonOf(err) != ReasonBadSignature {
			t.Errorf("%s: neden %q", name, ReasonOf(err))
		}
	}
	// Başka cihaz doğrulayıcısı.
	_, err = tVerify(d, tDevice2, tNow(), "cmdA")
	wantReason(t, err, ReasonWrongDevice)
	// Etki alanı etiketi: tek bit bozulursa ayrıştırma reddeder.
	msg := append([]byte(nil), d.Payload...)
	msg[5] ^= 0x01
	if _, err := ParseCanonicalV2(msg); err == nil {
		t.Fatal("bozuk etki alanı etiketi ayrıştı")
	}
	// Tel command_id / tip gövdeyle çelişirse.
	_, err = VerifyV2(d, tEnv().Params, VerifyInput{DeviceID: tDevice, Keys: tCmdKeys("cmdA"), Now: tNow(), WireCommandID: "a1b2c3d4-e5f6-4a07-98a9-b0c1d2e3f4a6"})
	wantReason(t, err, ReasonMalformedEnvelope)
	_, err = VerifyV2(d, tEnv().Params, VerifyInput{DeviceID: tDevice, Keys: tCmdKeys("cmdA"), Now: tNow(), WireType: TypeWipe})
	wantReason(t, err, ReasonMalformedEnvelope)
	if _, err = VerifyV2(d, tEnv().Params, VerifyInput{DeviceID: tDevice, Keys: tCmdKeys("cmdA"), Now: tNow(), WireCommandID: tEnv().CommandID, WireType: TypeQuarantine}); err != nil {
		t.Fatalf("tel değerleri gövdeyle aynıyken ret: %v", err)
	}
}

// N11: imza/anahtar boyutları ve boş anahtar kümesi panik atmaz.
func TestN11_SizesAndEmptyKeySet(t *testing.T) {
	d := tSigned(t)
	if _, err := VerifyV2(d, tEnv().Params, VerifyInput{DeviceID: tDevice, Now: tNow()}); ReasonOf(err) != ReasonUnknownKey {
		t.Fatalf("boş küme: %v", err)
	}
	x := d
	x.Signatures = []DSSESignature{{KeyID: d.Signatures[0].KeyID, Sig: d.Signatures[0].Sig[:63]}}
	_, err := tVerify(x, tDevice, tNow(), "cmdA")
	wantReason(t, err, ReasonMalformedEnvelope)
	bad := tCmdKeys("cmdA")
	bad[0].Pub = bad[0].Pub[:31]
	_, err = VerifyV2(d, tEnv().Params, VerifyInput{DeviceID: tDevice, Keys: bad, Now: tNow()})
	wantReason(t, err, ReasonUnknownKey)
	if VerifySignature(tPub("cmdA")[:5], []byte("x"), d.Signatures[0].Sig) {
		t.Fatal("kısa anahtar doğruladı")
	}
	if KeyID(tPub("cmdA")[:5]) != "" {
		t.Fatal("kısa anahtar için keyid boş olmalı")
	}
	if _, err := SignV2(ed25519.PrivateKey{1}, tDevice, tEnv()); err == nil {
		t.Fatal("kısa özel anahtar imzaladı")
	}
	rootAsCmd := tCmdKeys("cmdA")
	rootAsCmd[0].Role = KeyRoleRoot
	_, err = VerifyV2(d, tEnv().Params, VerifyInput{DeviceID: tDevice, Keys: rootAsCmd, Now: tNow()})
	wantReason(t, err, ReasonUnknownKey)
}

// N12: sunucu→JSONB→structpb→ajan yolunda özet değişmez.
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
	raw, _ := json.Marshal(m)
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	st, err := structpb.NewStruct(back)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := ParamsFromMap(st.AsMap())
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := ParamsDigest(wire); got != want {
		t.Fatal("özet JSON/structpb yolculuğunda değişti")
	}
}

// N13: yük türü sürümü — v1/v3 unsupported_version, başka tür bad_payload_type.
func TestN13_PayloadTypeVersion(t *testing.T) {
	for _, pt := range []string{"application/vnd.kut.cmd.v1", "application/vnd.kut.cmd.v3", "application/vnd.kut.cmd.v2.1", "application/vnd.kut.cmd."} {
		d := tSigned(t)
		d.PayloadType = pt
		_, err := tVerify(d, tDevice, tNow(), "cmdA")
		wantReason(t, err, ReasonUnsupportedVersion)
	}
	for _, pt := range []string{"", "application/json", "application/vnd.kut.trust.v2", "APPLICATION/VND.KUT.CMD.V2", " application/vnd.kut.cmd.v2"} {
		d := tSigned(t)
		d.PayloadType = pt
		_, err := tVerify(d, tDevice, tNow(), "cmdA")
		wantReason(t, err, ReasonBadPayloadType)
	}
	// Sonu boşluklu tür: sürüm öneki eşleşir ama tür tam eşit değil.
	d := tSigned(t)
	d.PayloadType = "application/vnd.kut.cmd.v2 "
	_, err := tVerify(d, tDevice, tNow(), "cmdA")
	wantReason(t, err, ReasonUnsupportedVersion)
	// Doğru tür etiketiyle sunulan ama başka türe göre atılmış imza.
	d = tSigned(t)
	d.Signatures = []DSSESignature{mustSig(t, "cmdA", "application/vnd.kut.cmd.v2 ", d.Payload)}
	_, err = tVerify(d, tDevice, tNow(), "cmdA")
	wantReason(t, err, ReasonBadSignature)
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
	e := tEnv()
	e.IssuedAtNS = tBase + int64(30*24*time.Hour)
	e.ExpiresAtNS = e.IssuedAtNS + int64(time.Hour)
	se, err := SignV2(tKey("cmdA"), tDevice, e)
	if err != nil {
		t.Fatal(err)
	}
	keys := tCmdKeys("cmdA")
	keys[0].NotAfterNS = tBase + int64(60*24*time.Hour)
	_, err = VerifyV2(se, tEnv().Params, VerifyInput{DeviceID: tDevice, Keys: keys, Now: tNow()})
	wantReason(t, err, ReasonNotYetValid)
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
	d := tSigned(t)
	_, err := tVerify(d, tDevice, time.Time{}, "cmdA")
	wantReason(t, err, ReasonClockUnsynced)
	if !ReasonOf(err).Transient() {
		t.Fatal("clock_unsynced geçici olmalı")
	}
	_, err = tVerify(d, tDevice, time.Unix(0, tEnv().ExpiresAtNS+1), "cmdA")
	wantReason(t, err, ReasonExpired)
	if ReasonOf(err).Transient() {
		t.Fatal("expired kalıcı olmalı")
	}
	if _, err := tVerify(d, tDevice, time.Unix(0, tEnv().ExpiresAtNS), "cmdA"); err != nil {
		t.Fatalf("tam bitiş anı geçerli: %v", err)
	}
}

// N136: her imzalı dizge için sınır/karakter kümesi (imzalamadan ÖNCE ve geçerli imzalı gövdede).
func TestN136_FieldLimits(t *testing.T) {
	type tc struct {
		name string
		env  func(*Envelope)
		body func(*Fields)
		want Reason
	}
	long := func(n int) string { return strings.Repeat("a", n) }
	M, P := ReasonMalformedEnvelope, ReasonMalformedParams
	cases := []tc{
		{"correlation 129", func(e *Envelope) { e.CorrelationID = long(129) }, func(f *Fields) { f.CorrelationID = long(129) }, M},
		{"correlation NUL", func(e *Envelope) { e.CorrelationID = "a\x00" }, func(f *Fields) { f.CorrelationID = "a\x00" }, M},
		{"correlation space", func(e *Envelope) { e.CorrelationID = "a b" }, func(f *Fields) { f.CorrelationID = "a b" }, M},
		{"correlation utf8", func(e *Envelope) { e.CorrelationID = "ü" }, func(f *Fields) { f.CorrelationID = "ü" }, M},
		{"correlation invalid utf8", func(e *Envelope) { e.CorrelationID = "\xff" }, func(f *Fields) { f.CorrelationID = "\xff" }, M},
		{"tenant 64", func(e *Envelope) { e.TenantID = long(64) }, func(f *Fields) { f.TenantID = long(64) }, M},
		{"tenant space", func(e *Envelope) { e.TenantID = "a b" }, func(f *Fields) { f.TenantID = "a b" }, M},
		{"requested_by empty", func(e *Envelope) { e.RequestedBy = "" }, func(f *Fields) { f.RequestedBy = "" }, M},
		{"requested_by 129", func(e *Envelope) { e.RequestedBy = long(129) }, func(f *Fields) { f.RequestedBy = long(129) }, M},
		{"requested_by 0x1f", func(e *Envelope) { e.RequestedBy = "a\x1fb" }, func(f *Fields) { f.RequestedBy = "a\x1fb" }, M},
		{"approved_by 129", func(e *Envelope) { e.ApprovedBy = long(129) }, func(f *Fields) { f.ApprovedBy = long(129) }, M},
		{"approved_by == requested_by", func(e *Envelope) { e.ApprovedBy = e.RequestedBy }, func(f *Fields) { f.ApprovedBy = f.RequestedBy }, M},
		{"command_id uppercase", func(e *Envelope) { e.CommandID = strings.ToUpper(e.CommandID) }, func(f *Fields) { f.CommandID = strings.ToUpper(f.CommandID) }, M},
		{"command_id braces", func(e *Envelope) { e.CommandID = "{" + e.CommandID + "}" }, func(f *Fields) { f.CommandID = "{" + f.CommandID + "}" }, M},
		{"command_id no hyphens", func(e *Envelope) { e.CommandID = strings.ReplaceAll(e.CommandID, "-", "") }, func(f *Fields) { f.CommandID = strings.ReplaceAll(f.CommandID, "-", "") }, M},
		{"command_id v1 uuid", func(e *Envelope) { e.CommandID = "11111111-1111-1111-8111-111111111111" }, func(f *Fields) { f.CommandID = "11111111-1111-1111-8111-111111111111" }, M},
		{"command_id bad variant", func(e *Envelope) { e.CommandID = "11111111-1111-4111-c111-111111111111" }, func(f *Fields) { f.CommandID = "11111111-1111-4111-c111-111111111111" }, M},
		{"nonce uppercase", func(e *Envelope) { e.Nonce = strings.ToUpper(e.Nonce) }, func(f *Fields) { f.Nonce = strings.ToUpper(f.Nonce) }, M},
		{"nonce 31", func(e *Envelope) { e.Nonce = e.Nonce[:31] }, func(f *Fields) { f.Nonce = f.Nonce[:31] }, M},
		{"nonce 33", func(e *Envelope) { e.Nonce += "0" }, func(f *Fields) { f.Nonce += "0" }, M},
		{"nonce non-hex", func(e *Envelope) { e.Nonce = strings.Repeat("g", 32) }, func(f *Fields) { f.Nonce = strings.Repeat("g", 32) }, M},
		{"type unknown", func(e *Envelope) { e.Type = "REBOOT" }, func(f *Fields) { f.Type = "REBOOT" }, ReasonUnknownType},
		{"type lowercase", func(e *Envelope) { e.Type = "quarantine" }, func(f *Fields) { f.Type = "quarantine" }, ReasonUnknownType},
		{"type padded", func(e *Envelope) { e.Type = " QUARANTINE" }, func(f *Fields) { f.Type = " QUARANTINE" }, ReasonUnknownType},
		{"type empty", func(e *Envelope) { e.Type = "" }, func(f *Fields) { f.Type = "" }, ReasonUnknownType},
		{"lifetime zero", func(e *Envelope) { e.ExpiresAtNS = e.IssuedAtNS }, func(f *Fields) { f.ExpiresAtNS = f.IssuedAtNS }, ReasonBadLifetime},
		{"lifetime 31d+1", func(e *Envelope) { e.ExpiresAtNS = e.IssuedAtNS + int64(MaxLifetime) + 1 }, func(f *Fields) { f.ExpiresAtNS = f.IssuedAtNS + int64(MaxLifetime) + 1 }, ReasonBadLifetime},
		{"params 33 keys", func(e *Envelope) {
			e.Params = nil
			for i := 0; i < 33; i++ {
				e.Params = append(e.Params, StringParam("k"+strings.Repeat("a", i/26)+string(rune('a'+i%26)), "v"))
			}
		}, nil, P},
		{"params key uppercase", func(e *Envelope) { e.Params = []Param{StringParam("Key", "v")} }, nil, P},
		{"params key empty", func(e *Envelope) { e.Params = []Param{StringParam("", "v")} }, nil, P},
		{"params key 65", func(e *Envelope) { e.Params = []Param{StringParam(long(65), "v")} }, nil, P},
		{"params dup key", func(e *Envelope) { e.Params = []Param{StringParam("a", "1"), StringParam("a", "2")} }, nil, P},
		{"params string 256KiB+1", func(e *Envelope) { e.Params = []Param{StringParam("a", long(MaxParamStringBytes+1))} }, nil, P},
		{"params list 65", func(e *Envelope) { e.Params = []Param{ListParam("a", make([]string, 65)...)} }, nil, P},
		{"params total 512KiB+", func(e *Envelope) {
			e.Params = []Param{StringParam("a", long(MaxParamStringBytes)), StringParam("b", long(MaxParamStringBytes)), StringParam("c", "x")}
		}, nil, P},
		{"params list+value", func(e *Envelope) { e.Params = []Param{{Key: "a", Value: "x", IsList: true}} }, nil, P},
		{"params string+list", func(e *Envelope) { e.Params = []Param{{Key: "a", Value: "x", List: []string{"y"}}} }, nil, P},
	}
	for _, c := range cases {
		e := tEnv()
		c.env(&e)
		if _, err := SignV2(tKey("cmdA"), tDevice, e); ReasonOf(err) != c.want {
			t.Errorf("%s: imzalama nedeni %q (%v), beklenen %q", c.name, ReasonOf(err), err, c.want)
		}
		if c.body != nil { // geçerli imzalı ama biçimsiz gövde doğrulamada da reddedilir
			d := tCrafted(t, c.body)
			if _, err := tVerify(d, tDevice, tNow(), "cmdA"); ReasonOf(err) != c.want {
				t.Errorf("%s: doğrulama nedeni %q (%v), beklenen %q", c.name, ReasonOf(err), err, c.want)
			}
		} else { // params: telde taşınan params değişir
			if _, err := VerifyV2(tSigned(t), e.Params, VerifyInput{DeviceID: tDevice, Keys: tCmdKeys("cmdA"), Now: tNow()}); ReasonOf(err) != c.want {
				t.Errorf("%s: doğrulama nedeni %q, beklenen %q", c.name, ReasonOf(err), c.want)
			}
		}
	}
	for name, id := range map[string]string{"64-bit": KeyID(tPub("cmdA"))[:16], "uppercase": strings.ToUpper(KeyID(tPub("cmdA"))), "empty": ""} {
		d := tSigned(t)
		d.Signatures[0].KeyID = id
		if _, err := tVerify(d, tDevice, tNow(), "cmdA"); ReasonOf(err) != ReasonMalformedEnvelope {
			t.Errorf("keyid %s: neden %q", name, ReasonOf(err))
		}
	}
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
	_, err := tVerify(tCrafted(t, func(f *Fields) { f.DeviceID = "0B1c2d3e-4f50-4a61-8b72-93a4b5c6d7e8" }), tDevice, tNow(), "cmdA")
	wantReason(t, err, ReasonBadDeviceID)
	e := tEnv()
	e.CorrelationID = strings.Repeat("a", 128)
	e.RequestedBy = strings.Repeat("r", 128)
	e.ApprovedBy = strings.Repeat("p", 128)
	e.TenantID = strings.Repeat("t", 63)
	d, err := SignV2(tKey("cmdA"), strings.Repeat("d", 64), e)
	if err != nil {
		t.Fatalf("sınır değerleri geçerli olmalı: %v", err)
	}
	if len(d.Payload) > MaxDSSEPayloadBytes {
		t.Fatalf("azami komut gövdesi %d bayt > %d", len(d.Payload), MaxDSSEPayloadBytes)
	}
}

func TestParamsLimitsAtBoundary(t *testing.T) {
	if err := ValidateParams([]Param{StringParam("a", strings.Repeat("a", MaxParamStringBytes))}); err != nil {
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

// Katı ayrıştırıcılar: artık bayt, kısaltma, sırasız/yinelenen params, aşırı uzunluk.
func TestStrictParsers(t *testing.T) {
	msg := tSigned(t).Payload
	if _, err := ParseCanonicalV2(append(append([]byte(nil), msg...), 0)); err == nil {
		t.Fatal("artık bayt kabul edildi")
	}
	for i := 0; i < len(msg); i++ {
		if _, err := ParseCanonicalV2(msg[:i]); err == nil {
			t.Fatalf("kısaltılmış girdi (%d bayt) kabul edildi", i)
		}
	}
	big := append([]byte(nil), msg...)
	big[4+19+3] = 0xff // command_id uzunluğunun son baytı
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
	bad[len(bad)-6] = 0x09
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

// Çoklu imza (D1: komut imzası + onaylayan imzası): gövde aynı, imzalar DSSE listesinde.
func TestMultiSignature(t *testing.T) {
	d, err := CoSign(tKey("cmdB"), tSigned(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, trusted := range [][]string{{"cmdA"}, {"cmdB"}, {"cmdA", "cmdB"}} {
		v, err := tVerify(d, tDevice, tNow(), trusted...)
		if err != nil {
			t.Fatalf("%v güvenen ajan reddetti: %v", trusted, err)
		}
		if len(v.KeyIDs) != len(trusted) {
			t.Errorf("%v: geçerli imza sayısı %d", trusted, len(v.KeyIDs))
		}
	}
	in := func(n int, keys ...string) VerifyInput {
		return VerifyInput{DeviceID: tDevice, Keys: tCmdKeys(keys...), Now: tNow(), MinSignatures: n}
	}
	if _, err := VerifyV2(d, tEnv().Params, in(2, "cmdA", "cmdB")); err != nil {
		t.Fatalf("2-of-2: %v", err)
	}
	_, err = VerifyV2(d, tEnv().Params, in(2, "cmdA"))
	wantReason(t, err, ReasonInsufficientSignatures)
	_, err = VerifyV2(tSigned(t), tEnv().Params, in(2, "cmdA", "cmdB"))
	wantReason(t, err, ReasonInsufficientSignatures)
	dup := tSigned(t)
	dup.Signatures = append(dup.Signatures, dup.Signatures[0])
	_, err = VerifyV2(dup, tEnv().Params, in(2, "cmdA", "cmdB"))
	wantReason(t, err, ReasonInsufficientSignatures)
	if _, err := VerifyV2(dup, tEnv().Params, in(1, "cmdA")); err != nil {
		t.Fatalf("yinelenen keyid tek imza için engel olmamalı: %v", err)
	}
	unk, _ := CoSign(tKey("evil"), tSigned(t))
	if _, err := tVerify(unk, tDevice, tNow(), "cmdA"); err != nil {
		t.Fatalf("bilinmeyen ek imza engel olmamalı: %v", err)
	}
	_, err = tVerify(d, tDevice, tNow(), "cmdC")
	wantReason(t, err, ReasonUnknownKey)
	badSec := d
	badSec.Signatures = append([]DSSESignature(nil), d.Signatures...)
	badSec.Signatures[1].Sig = append([]byte(nil), d.Signatures[1].Sig...)
	badSec.Signatures[1].Sig[0] ^= 1
	_, err = VerifyV2(badSec, tEnv().Params, in(2, "cmdA", "cmdB"))
	wantReason(t, err, ReasonBadSignature)
	if _, err := VerifyV2(badSec, tEnv().Params, in(1, "cmdA", "cmdB")); err != nil {
		t.Fatalf("1 imza yeterliyken bozuk ikinci imza reddettirmemeli: %v", err)
	}
	full := tSigned(t)
	for i := 0; len(full.Signatures) < MaxDSSESignatures; i++ {
		var err error
		if full, err = CoSign(tKey("extra"+string(rune('a'+i))), full); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := CoSign(tKey("extra-overflow"), full); err == nil {
		t.Fatal("9. imza eklenebildi")
	}
}

// N111 (zarf yarısı): anahtar penceresi issued_at anına göre değerlendirilir.
func TestKeyWindowUsesIssuedAt(t *testing.T) {
	d := tSigned(t) // issued = tBase
	vi := func(k []KeyEntry) (Verified, error) {
		return VerifyV2(d, tEnv().Params, VerifyInput{DeviceID: tDevice, Keys: k, Now: tNow()})
	}
	k := tCmdKeys("cmdA")
	k[0].NotBeforeNS = tBase + 1
	_, err := vi(k)
	wantReason(t, err, ReasonKeyExpired)
	k = tCmdKeys("cmdA")
	k[0].NotAfterNS = tBase - 1
	_, err = vi(k)
	wantReason(t, err, ReasonKeyExpired)
	k = tCmdKeys("cmdA")
	k[0].NotAfterNS = tBase
	if _, err := vi(k); err != nil {
		t.Fatalf("issued==not_after kabul edilmeli: %v", err)
	}
	k = tCmdKeys("cmdA")
	k[0].NotAfterNS = 0
	_, err = vi(k)
	wantReason(t, err, ReasonKeyExpired)
}

func TestSignV2ProducesDSSE(t *testing.T) {
	d, err := SignV2(tKey("cmdA"), tDevice, tEnv())
	if err != nil {
		t.Fatal(err)
	}
	if d.PayloadType != PayloadTypeCommand || len(d.Signatures) != 1 || len(d.Signatures[0].Sig) != 64 || d.Signatures[0].KeyID != KeyID(tPub("cmdA")) {
		t.Fatalf("SignV2 çıktısı: %v %+v", d, d.Signatures)
	}
	if !ed25519.Verify(tPub("cmdA"), PAE(PayloadTypeCommand, d.Payload), d.Signatures[0].Sig) {
		t.Fatal("imza PAE üzerinde değil")
	}
}

func TestSequenceEncodingU64(t *testing.T) {
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
	for _, r := range []Reason{ReasonBadSignature, ReasonExpired, ReasonKeyExpired, ReasonMalformedEnvelope, ReasonUnknownType, ReasonBadLifetime,
		ReasonUnsupportedVersion, ReasonBadPayloadType, ReasonWrongDevice, ReasonInsufficientSignatures} {
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
		if _, err := VerifyV2(se, e.Params, VerifyInput{DeviceID: tDevice, Keys: tCmdKeys("cmdA"), Now: tNow()}); err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
	}
	if RequiredSignatures(TypeWipe) != 1 {
		t.Fatal("W2'de gereken imza sayısı 1 olmalı (2-of-N kancası ayrılmıştır)")
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
