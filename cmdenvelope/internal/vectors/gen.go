package vectors

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"kut.corp/suite/cmdenvelope"
)

// Sabit sınır değerleri. Tüm zamanlar sabit bir referans andan (BaseNS) türer; gerçek
// saate hiçbir yerde bakılmaz.
const (
	BaseNS = int64(1_790_000_000_000_000_000)
	// Device / Device2: iki farklı cihaz kimliği (küçük harfli UUID).
	Device  = "0b1c2d3e-4f50-4a61-8b72-93a4b5c6d7e8"
	Device2 = "1c2d3e4f-5061-4b72-9c83-a4b5c6d7e8f9"

	hour = int64(time.Hour)
	day  = 24 * hour
)

var seedNames = []string{"root1", "root2", "root3", "root4", "root5", "cmdA", "cmdB", "cmdC", "evil"}

func priv(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("kut-w2-vector-seed:" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func pub(name string) ed25519.PublicKey { return priv(name).Public().(ed25519.PublicKey) }

func rootKey(name string) cmdenvelope.KeyEntry {
	p := pub(name)
	return cmdenvelope.KeyEntry{KeyID: cmdenvelope.KeyID(p), Pub: p, Role: cmdenvelope.KeyRoleRoot}
}

func cmdKey(name string, nb, na int64) cmdenvelope.KeyEntry {
	p := pub(name)
	return cmdenvelope.KeyEntry{KeyID: cmdenvelope.KeyID(p), Pub: p, Role: cmdenvelope.KeyRoleCommand, NotBeforeNS: nb, NotAfterNS: na}
}

func idOf(name string) string { return cmdenvelope.KeyID(pub(name)) }

type gen struct {
	err error
}

func (g *gen) must(err error) {
	if err != nil && g.err == nil {
		g.err = err
	}
}

// Generate, vektör dosyasının BAYT-BAYT deterministik JSON halini üretir.
func Generate() ([]byte, error) {
	g := &gen{}
	f := File{
		Format: FormatVersion,
		Description: "DSSE tabanlı komut zarfı v2 (application/vnd.kut.cmd.v2) ve güven bildirimi " +
			"(application/vnd.kut.trust.v2) altın vektörleri. Tohumlar sabittir; imzalar deterministiktir. " +
			"Sunucu ve ajan testleri bu dosyayı aynen okur.",
	}
	for _, n := range seedNames {
		seed := sha256.Sum256([]byte("kut-w2-vector-seed:" + n))
		f.Seeds = append(f.Seeds, SeedJSON{Name: n, SeedHex: hex.EncodeToString(seed[:]), PubHex: hex.EncodeToString(pub(n)), KeyID: idOf(n)})
	}
	f.PAE = paeCases()
	f.Envelopes = g.envelopes()
	f.Params = g.paramCases()
	f.ParamMaps = paramMapCases()
	f.Scenarios = g.scenarios()
	if g.err != nil {
		return nil, g.err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func paeCases() []PAECase {
	mk := func(name, pt string, payload []byte) PAECase {
		return PAECase{Name: name, PayloadType: pt, PayloadHex: hex.EncodeToString(payload), PAEHex: hex.EncodeToString(cmdenvelope.PAE(pt, payload))}
	}
	return []PAECase{
		mk("dsse-spec-example", "http://example.com/HelloWorld", []byte("hello world")),
		mk("command-type-empty-payload", cmdenvelope.PayloadTypeCommand, nil),
		mk("trust-type-binary-payload", cmdenvelope.PayloadTypeTrust, []byte{0x00, 0x01, 0xff, 0x20, 0x41}),
		mk("long-type-three-digit-length", strings.Repeat("t", 100), []byte("x")),
	}
}

// ---- zarf vektörleri ---------------------------------------------------------

func baseEnv() cmdenvelope.Envelope {
	return cmdenvelope.Envelope{
		CommandID: "a1b2c3d4-e5f6-4a07-98a9-b0c1d2e3f4a5", TenantID: "", Type: cmdenvelope.TypeQuarantine,
		RequestedBy: "admin:9f8e7d6c-5b4a-4392-8180-706f5e4d3c2b",
		Sequence:    0, Nonce: "00112233445566778899aabbccddeeff",
		IssuedAtNS: BaseNS, ExpiresAtNS: BaseNS + 7*day,
	}
}

func trustedKeys(names ...string) []cmdenvelope.KeyEntry {
	var out []cmdenvelope.KeyEntry
	for _, n := range names {
		out = append(out, cmdKey(n, BaseNS-hour, BaseNS+90*day))
	}
	return out
}

func nowOK() int64 { return BaseNS + int64(time.Minute) }

type envOpt func(*EnvelopeCase)

func withDevice(d string) envOpt { return func(c *EnvelopeCase) { c.DeviceID = d } }
func withNow(n int64) envOpt     { return func(c *EnvelopeCase) { c.NowNS = n } }
func withMin(n int) envOpt       { return func(c *EnvelopeCase) { c.MinSignatures = n } }
func withWire(id, typ string) envOpt {
	return func(c *EnvelopeCase) { c.WireCommandID, c.WireType = id, typ }
}
func withKeys(ks ...cmdenvelope.KeyEntry) envOpt {
	return func(c *EnvelopeCase) {
		c.Keys = nil
		for _, k := range ks {
			c.Keys = append(c.Keys, KeyToJSON(k))
		}
	}
}

// addCase, bir zarf vektörü ekler. Gövde/PAE/özet alanları dosyaya yazılır; gövde
// ayrıştırılabiliyorsa çözülmüş görünüm de eklenir.
func (g *gen) addCase(out *[]EnvelopeCase, name, doc, expect string, d cmdenvelope.DSSE, params []cmdenvelope.Param, opts ...envOpt) {
	c := EnvelopeCase{
		Name: name, Doc: doc, DeviceID: Device, NowNS: nowOK(), Expect: expect,
		DSSE: DSSEToJSON(d), Params: ParamsToJSON(params),
	}
	withKeys(trustedKeys("cmdA")...)(&c)
	for _, o := range opts {
		o(&c)
	}
	pae := cmdenvelope.PAE(d.PayloadType, d.Payload)
	sum := sha256.Sum256(pae)
	c.PayloadHex = hex.EncodeToString(d.Payload)
	c.PAEHex = hex.EncodeToString(pae)
	c.DigestHex = hex.EncodeToString(sum[:])
	if f, err := cmdenvelope.ParseCanonicalV2(d.Payload); err == nil {
		c.Body = &BodyJSON{
			CommandID: f.CommandID, DeviceID: f.DeviceID, TenantID: f.TenantID, Type: f.Type,
			RequestedBy: f.RequestedBy, ApprovedBy: f.ApprovedBy, CorrelationID: f.CorrelationID,
			Sequence: f.Sequence, Nonce: f.Nonce, IssuedAtNS: f.IssuedAtNS, ExpiresAtNS: f.ExpiresAtNS,
			ParamsDigestHex: hex.EncodeToString(f.ParamsDigest[:]),
		}
	}
	*out = append(*out, c)
}

func (g *gen) sign(name string, env cmdenvelope.Envelope) cmdenvelope.DSSE {
	d, err := cmdenvelope.SignV2(priv(name), Device, env)
	g.must(err)
	return d
}

func (g *gen) cosign(name string, d cmdenvelope.DSSE) cmdenvelope.DSSE {
	x, err := cmdenvelope.CoSign(priv(name), d)
	g.must(err)
	return x
}

func (g *gen) rawSig(name, payloadType string, payload []byte) cmdenvelope.DSSESignature {
	s, err := cmdenvelope.SignDSSE(priv(name), payloadType, payload)
	g.must(err)
	return s
}

// mutPayload, imzalı zarfın gövdesini değiştirir ve ESKİ imzaları korur (imzadan sonra kurcalama).
func (g *gen) mutPayload(d cmdenvelope.DSSE, f func(*cmdenvelope.Fields)) cmdenvelope.DSSE {
	fl, err := cmdenvelope.ParseCanonicalV2(d.Payload)
	g.must(err)
	f(&fl)
	d.Payload = fl.EncodeUnvalidated()
	return d
}

// crafted, taban gövdeye mod uygular ve cmdA ile GEÇERLİ imzalar: imza doğru ama gövde biçimsiz.
func (g *gen) crafted(mod func(*cmdenvelope.Fields)) cmdenvelope.DSSE {
	f, err := baseEnv().Fields(Device)
	g.must(err)
	mod(&f)
	body := f.EncodeUnvalidated()
	return cmdenvelope.DSSE{PayloadType: cmdenvelope.PayloadTypeCommand, Payload: body,
		Signatures: []cmdenvelope.DSSESignature{g.rawSig("cmdA", cmdenvelope.PayloadTypeCommand, body)}}
}

func longStr(c byte, n int) string { return strings.Repeat(string(c), n) }

func (g *gen) envelopes() []EnvelopeCase {
	var out []EnvelopeCase
	add := func(name, doc, expect string, d cmdenvelope.DSSE, params []cmdenvelope.Param, opts ...envOpt) {
		g.addCase(&out, name, doc, expect, d, params, opts...)
	}
	pos := func(name, doc string, env cmdenvelope.Envelope, opts ...envOpt) {
		add(name, doc, "ok", g.sign("cmdA", env), env.Params, opts...)
	}

	// ---- pozitif ----
	pos("baseline-quarantine", "en küçük geçerli zarf: sequence 0, boş kiracı, boş params", baseEnv())

	e := baseEnv()
	e.Sequence, e.TenantID, e.CorrelationID = 0x0102030405060708, "acme", "req-0001"
	e.Params = []cmdenvelope.Param{cmdenvelope.StringParam("reason", "ransomware")}
	pos("nonzero-sequence", "sequence 8 bayt büyük-endian (2^32 üzeri)", e)

	e = baseEnv()
	e.Sequence = ^uint64(0)
	pos("max-sequence", "uint64 üst sınır", e)

	// Çoklu imza: komut imzası + ikinci imzacı (ör. onaylayan); gövde AYNI.
	e = baseEnv()
	e.TenantID = "acme"
	prim := g.sign("cmdA", e)
	two := g.cosign("cmdB", prim)
	add("two-signatures-both-trusted", "cmdA + cmdB aynı gövdeyi imzalar; ajan ikisine de güveniyor, 2 imza gerekiyor", "ok", two, e.Params,
		withKeys(trustedKeys("cmdA", "cmdB")...), withMin(2))
	add("two-signatures-secondary-only-trusted", "aynı zarf; ajan yalnız cmdB'ye güveniyor (rotasyon örtüşmesi)", "ok", two, e.Params, withKeys(trustedKeys("cmdB")...))
	add("two-signatures-primary-only-trusted", "aynı zarf; ajan yalnız cmdA'ya güveniyor", "ok", two, e.Params, withKeys(trustedKeys("cmdA")...))
	unk := g.cosign("evil", prim)
	add("unknown-extra-signer-ignored", "bilinmeyen ek imzacı yok sayılır, güvenilen imza yeter", "ok", unk, e.Params)
	dupSig := prim
	dupSig.Signatures = append(append([]cmdenvelope.DSSESignature(nil), prim.Signatures...), prim.Signatures[0])
	add("duplicate-keyid-counted-once", "aynı keyid iki kez: 1 imza gerekiyorsa kabul", "ok", dupSig, e.Params)
	add("duplicate-keyid-not-two-signatures", "aynı keyid iki kez ama 2 imza gerekiyor: yinelenen bir kez sayılır",
		string(cmdenvelope.ReasonInsufficientSignatures), dupSig, e.Params, withKeys(trustedKeys("cmdA", "cmdB")...), withMin(2))
	add("second-signature-required-but-missing", "2 imza gerekiyor, zarfta yalnız biri var", string(cmdenvelope.ReasonInsufficientSignatures),
		prim, e.Params, withKeys(trustedKeys("cmdA", "cmdB")...), withMin(2))
	add("second-signer-not-trusted", "2 imza gerekiyor, ikinci imzacı güvenilen kümede değil", string(cmdenvelope.ReasonInsufficientSignatures),
		two, e.Params, withKeys(trustedKeys("cmdA")...), withMin(2))
	badSecond := two
	badSecond.Signatures = append([]cmdenvelope.DSSESignature(nil), two.Signatures...)
	badSecond.Signatures[1].Sig = append([]byte(nil), two.Signatures[1].Sig...)
	badSecond.Signatures[1].Sig[0] ^= 1
	add("second-signature-corrupt-one-required", "ikinci imza bozuk ama 1 imza yeterli: kabul", "ok", badSecond, e.Params, withKeys(trustedKeys("cmdA", "cmdB")...))
	add("second-signature-corrupt-two-required", "ikinci imza bozuk ve 2 imza gerekiyor", string(cmdenvelope.ReasonBadSignature),
		badSecond, e.Params, withKeys(trustedKeys("cmdA", "cmdB")...), withMin(2))

	// Çift kontrollü tipler: onaylayan imzası (ikinci DSSE imzası) ile. approved_by ↔ anahtar
	// bağı ve 2-of-N'in etkinleştirilmesi ayrı bileşenlerin işidir (MinSignatures kancası hazır).
	e = baseEnv()
	e.Type = cmdenvelope.TypeWipe
	e.ApprovedBy = "admin:1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
	e.Params = []cmdenvelope.Param{cmdenvelope.StringParam("scope", "user_data")}
	wipe := g.sign("cmdA", e)
	add("dual-control-wipe-approver-signature", "WIPE: komut imzası + onaylayan imzası, 2 imza gerekiyor", "ok", g.cosign("cmdB", wipe), e.Params,
		withKeys(trustedKeys("cmdA", "cmdB")...), withMin(2))
	add("dual-control-wipe-approver-signature-missing", "WIPE: yalnız komut imzası var, 2 imza gerekiyor",
		string(cmdenvelope.ReasonInsufficientSignatures), wipe, e.Params, withKeys(trustedKeys("cmdA", "cmdB")...), withMin(2))

	classes := []struct {
		typ, doc string
		mod      func(*cmdenvelope.Envelope)
	}{
		{cmdenvelope.TypeQuarantine, "izolasyon", func(e *cmdenvelope.Envelope) {
			e.Params = []cmdenvelope.Param{cmdenvelope.StringParam("reason", "ransomware")}
		}},
		{cmdenvelope.TypeUnquarantine, "izolasyon kaldırma", func(e *cmdenvelope.Envelope) {}},
		{cmdenvelope.TypeLock, "ekran kilidi", func(e *cmdenvelope.Envelope) {}},
		{cmdenvelope.TypeRestart, "yeniden başlatma", func(e *cmdenvelope.Envelope) {
			e.Params = []cmdenvelope.Param{cmdenvelope.StringParam("delay_seconds", "30")}
		}},
		{cmdenvelope.TypeWipe, "veri silme; çift kontrol: approved_by ≠ requested_by", func(e *cmdenvelope.Envelope) {
			e.ApprovedBy = "admin:1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
			e.Params = []cmdenvelope.Param{cmdenvelope.StringParam("scope", "user_data")}
		}},
		{cmdenvelope.TypeRunSignedScript, "imzalı betik: dize ve liste param", func(e *cmdenvelope.Envelope) {
			e.ExpiresAtNS = BaseNS + hour
			e.Params = []cmdenvelope.Param{
				cmdenvelope.StringParam("interpreter", "powershell"),
				cmdenvelope.StringParam("script_sig", "c2lnbmF0dXJlLWJ5dGVz"),
				cmdenvelope.ListParam("args", "-NoProfile", "-File", "C:\\ops\\check.ps1"),
			}
		}},
		{cmdenvelope.TypeCollectFile, "adli dosya toplama", func(e *cmdenvelope.Envelope) {
			e.Params = []cmdenvelope.Param{cmdenvelope.StringParam("path", "C:\\Users\\kullanıcı\\belge.txt")}
		}},
		{cmdenvelope.TypeCollectDiagnostics, "tanılama", func(e *cmdenvelope.Envelope) {}},
		{cmdenvelope.TypeUninstall, "kaldırma; çift kontrol", func(e *cmdenvelope.Envelope) {
			e.ApprovedBy = "admin:1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
		}},
	}
	for i, c := range classes {
		e := baseEnv()
		e.Type = c.typ
		e.CommandID = fmt.Sprintf("a1b2c3d4-e5f6-4a07-98a9-b0c1d2e3f4%02x", 0xa0+i)
		e.Nonce = fmt.Sprintf("%032x", i+1)
		e.TenantID = "acme"
		e.CorrelationID = "req-" + strings.ToLower(c.typ)
		e.Sequence = uint64(i + 1)
		c.mod(&e)
		pos("type-"+strings.ToLower(c.typ), c.doc, e)
	}

	e = baseEnv()
	e.Type = cmdenvelope.TypeCollectFile
	// params anahtarları küçük ASCII olmalıdır; unicode yalnız değerlerde bulunur.
	e.Params = []cmdenvelope.Param{
		cmdenvelope.StringParam("path", "çğış/日本語/😀"),
		cmdenvelope.ListParam("tags", "b", "", "ü", "a"),
		cmdenvelope.ListParam("none"),
		cmdenvelope.StringParam("empty", ""),
	}
	pos("unicode-params", "unicode değerler, boş dize, boş liste, liste sırası korunur", e)

	e = baseEnv()
	for i := 0; i < cmdenvelope.MaxParamKeys; i++ {
		e.Params = append(e.Params, cmdenvelope.StringParam(fmt.Sprintf("k%02d", 31-i), fmt.Sprintf("v%d", i)))
	}
	pos("max-params-32-keys", "32 anahtar, ters sırada verildi (özet sıralıdır)", e)

	e = baseEnv()
	e.ExpiresAtNS = e.IssuedAtNS + int64(cmdenvelope.MaxLifetime)
	pos("lifetime-exactly-31d", "ömür tam 31 gün", e)

	e = baseEnv()
	e.IssuedAtNS = BaseNS + 90*day
	e.ExpiresAtNS = e.IssuedAtNS + hour
	pos("key-window-upper-edge", "issued_at == key.not_after: kabul", e,
		withNow(e.IssuedAtNS+int64(time.Minute)), withKeys(cmdKey("cmdA", BaseNS-hour, e.IssuedAtNS)))

	e = baseEnv()
	e.CorrelationID, e.RequestedBy, e.ApprovedBy, e.TenantID = longStr('c', 128), longStr('r', 128), longStr('p', 128), longStr('t', 63)
	pos("principal-limits-max", "requested_by/approved_by/correlation 128, tenant 63 bayt", e)

	pos("key-expired-after-issue-still-valid", "anahtar issued_at'ta geçerliydi; teslim anında dolmuş olsa da kabul", baseEnv(),
		withNow(BaseNS+hour), withKeys(cmdKey("cmdA", BaseNS-hour, BaseNS+hour/2)))

	// ---- negatif: DSSE zarfı ----
	baseD := g.sign("cmdA", baseEnv())
	bp := baseEnv().Params
	withType := func(pt string) cmdenvelope.DSSE { x := baseD; x.PayloadType = pt; return x }
	add("payload-type-v1", "payloadType sürüm 1", string(cmdenvelope.ReasonUnsupportedVersion), withType("application/vnd.kut.cmd.v1"), bp)
	add("payload-type-v3", "payloadType sürüm 3", string(cmdenvelope.ReasonUnsupportedVersion), withType("application/vnd.kut.cmd.v3"), bp)
	add("payload-type-trailing-space", "payloadType sonunda boşluk", string(cmdenvelope.ReasonUnsupportedVersion), withType("application/vnd.kut.cmd.v2 "), bp)
	add("payload-type-trust-on-command", "güven bildirimi türü komut zarfı olarak sunuldu", string(cmdenvelope.ReasonBadPayloadType), withType(cmdenvelope.PayloadTypeTrust), bp)
	add("payload-type-unrelated", "ilgisiz yük türü", string(cmdenvelope.ReasonBadPayloadType), withType("application/json"), bp)
	add("payload-type-empty", "boş yük türü", string(cmdenvelope.ReasonBadPayloadType), withType(""), bp)
	add("payload-type-uppercase", "büyük harfli yük türü", string(cmdenvelope.ReasonBadPayloadType), withType("APPLICATION/VND.KUT.CMD.V2"), bp)

	rawSigned := baseD
	rawSigned.Signatures = []cmdenvelope.DSSESignature{{KeyID: idOf("cmdA"), Sig: ed25519.Sign(priv("cmdA"), baseD.Payload)}}
	add("signature-over-body-without-pae", "imza PAE olmadan doğrudan gövde üzerinde", string(cmdenvelope.ReasonBadSignature), rawSigned, bp)
	otherType := baseD
	otherType.Signatures = []cmdenvelope.DSSESignature{g.rawSig("cmdA", cmdenvelope.PayloadTypeTrust, baseD.Payload)}
	add("signature-under-other-payload-type", "imza başka bir yük türüyle atılmış (PAE farklı)", string(cmdenvelope.ReasonBadSignature), otherType, bp)
	v1Bytes := cmdenvelope.CanonicalBytes(baseEnv().CommandID, Device, baseEnv().Type, baseEnv().RequestedBy, nil, baseEnv().Nonce, baseEnv().IssuedAtNS, baseEnv().ExpiresAtNS)
	v1Signed := baseD
	v1Signed.Signatures = []cmdenvelope.DSSESignature{{KeyID: idOf("cmdA"), Sig: ed25519.Sign(priv("cmdA"), v1Bytes)}}
	add("v1-signature-presented-as-v2", "v1 kanonik baytları üzerindeki imza v2 olarak sunuldu", string(cmdenvelope.ReasonBadSignature), v1Signed, bp)
	stmtBytes := trustBody(g)
	stmtSigned := baseD
	stmtSigned.Signatures = []cmdenvelope.DSSESignature{{KeyID: idOf("cmdA"), Sig: ed25519.Sign(priv("cmdA"), stmtBytes)}}
	add("trust-statement-signature-presented-as-envelope", "bildirim baytları üzerindeki imza zarf olarak sunuldu", string(cmdenvelope.ReasonBadSignature), stmtSigned, bp)
	hint := baseD
	hint.Signatures = []cmdenvelope.DSSESignature{{KeyID: idOf("cmdB"), Sig: baseD.Signatures[0].Sig}}
	add("keyid-hint-points-at-wrong-key", "cmdA imzası cmdB keyid'siyle sunuldu; ikisi de güvenilir → cmdB anahtarıyla doğrulanamaz",
		string(cmdenvelope.ReasonBadSignature), hint, bp, withKeys(trustedKeys("cmdA", "cmdB")...))
	unknownHint := baseD
	unknownHint.Signatures = []cmdenvelope.DSSESignature{{KeyID: idOf("evil"), Sig: baseD.Signatures[0].Sig}}
	add("keyid-unknown", "bilinmeyen keyid (geçici: bildirim henüz gelmedi)", string(cmdenvelope.ReasonUnknownKey), unknownHint, bp)
	shape := func(name, doc string, mod func(*cmdenvelope.DSSE)) {
		x := baseD
		x.Signatures = append([]cmdenvelope.DSSESignature(nil), baseD.Signatures...)
		mod(&x)
		add(name, doc, string(cmdenvelope.ReasonMalformedEnvelope), x, bp)
	}
	shape("signatures-empty", "imza listesi boş", func(x *cmdenvelope.DSSE) { x.Signatures = nil })
	shape("signature-63-bytes", "imza 63 bayt", func(x *cmdenvelope.DSSE) {
		x.Signatures = []cmdenvelope.DSSESignature{{KeyID: idOf("cmdA"), Sig: baseD.Signatures[0].Sig[:63]}}
	})
	shape("keyid-64-bit", "64-bit (16 hex) keyid", func(x *cmdenvelope.DSSE) {
		x.Signatures = []cmdenvelope.DSSESignature{{KeyID: idOf("cmdA")[:16], Sig: baseD.Signatures[0].Sig}}
	})
	shape("keyid-uppercase", "büyük harfli keyid", func(x *cmdenvelope.DSSE) {
		x.Signatures = []cmdenvelope.DSSESignature{{KeyID: strings.ToUpper(idOf("cmdA")), Sig: baseD.Signatures[0].Sig}}
	})
	shape("nine-signatures", "9 imza girdisi (sınır 8)", func(x *cmdenvelope.DSSE) {
		x.Signatures = nil
		for i := 0; i < 9; i++ {
			x.Signatures = append(x.Signatures, baseD.Signatures[0])
		}
	})
	shape("payload-empty", "boş gövde", func(x *cmdenvelope.DSSE) { x.Payload = nil })
	shape("payload-over-4096", "gövde 4097 bayt", func(x *cmdenvelope.DSSE) { x.Payload = make([]byte, cmdenvelope.MaxDSSEPayloadBytes+1) })
	eight := baseD
	for i := 0; len(eight.Signatures) < cmdenvelope.MaxDSSESignatures; i++ {
		eight = g.cosign(fmt.Sprintf("cmdC%d", i), eight)
	}
	add("eight-signatures-ok", "tam 8 imza girdisi (sınır): bilinmeyenler yok sayılır", "ok", eight, bp)

	// ---- negatif: gövde alanları (imza GEÇERLİ, gövde biçimsiz) ----
	m := string(cmdenvelope.ReasonMalformedEnvelope)
	bad := func(name, doc, reason string, mod func(*cmdenvelope.Fields)) {
		add(name, doc, reason, g.crafted(mod), bp)
	}
	bad("command-id-uppercase", "büyük harfli UUID (dedup takma adı)", m, func(f *cmdenvelope.Fields) { f.CommandID = strings.ToUpper(f.CommandID) })
	bad("command-id-braces", "süslü parantezli UUID", m, func(f *cmdenvelope.Fields) { f.CommandID = "{" + f.CommandID + "}" })
	bad("command-id-no-hyphens", "tiresiz UUID", m, func(f *cmdenvelope.Fields) { f.CommandID = strings.ReplaceAll(f.CommandID, "-", "") })
	bad("command-id-not-v4", "sürüm 1 UUID", m, func(f *cmdenvelope.Fields) { f.CommandID = "a1b2c3d4-e5f6-1a07-98a9-b0c1d2e3f4a5" })
	bad("nonce-uppercase-hex", "nonce büyük harfli hex", m, func(f *cmdenvelope.Fields) { f.Nonce = strings.ToUpper("aabbccddeeff00112233445566778899") })
	bad("nonce-31-chars", "nonce 31 karakter", m, func(f *cmdenvelope.Fields) { f.Nonce = f.Nonce[:31] })
	bad("correlation-id-nul", "correlation_id içinde NUL", m, func(f *cmdenvelope.Fields) { f.CorrelationID = "req\x0001" })
	bad("correlation-id-overlong", "correlation_id 129 bayt", m, func(f *cmdenvelope.Fields) { f.CorrelationID = longStr('c', 129) })
	bad("tenant-id-space", "tenant_id içinde boşluk", m, func(f *cmdenvelope.Fields) { f.TenantID = "ac me" })
	bad("tenant-id-overlong", "tenant_id 64 bayt", m, func(f *cmdenvelope.Fields) { f.TenantID = longStr('t', 64) })
	bad("requested-by-0x1f", "requested_by içinde 0x1f", m, func(f *cmdenvelope.Fields) { f.RequestedBy = "admin:a\x1fb" })
	bad("requested-by-empty", "requested_by boş", m, func(f *cmdenvelope.Fields) { f.RequestedBy = "" })
	bad("approved-by-equals-requested", "approved_by == requested_by", m, func(f *cmdenvelope.Fields) { f.ApprovedBy = f.RequestedBy })
	bad("type-empty", "tip boş (UNSPECIFIED eşleniği)", string(cmdenvelope.ReasonUnknownType), func(f *cmdenvelope.Fields) { f.Type = "" })
	bad("type-unknown", "bilinmeyen tip", string(cmdenvelope.ReasonUnknownType), func(f *cmdenvelope.Fields) { f.Type = "REBOOT" })
	bad("type-lowercase", "küçük harfli tip", string(cmdenvelope.ReasonUnknownType), func(f *cmdenvelope.Fields) { f.Type = "quarantine" })
	bad("lifetime-zero", "expires == issued", string(cmdenvelope.ReasonBadLifetime), func(f *cmdenvelope.Fields) { f.ExpiresAtNS = f.IssuedAtNS })
	bad("lifetime-negative", "expires < issued", string(cmdenvelope.ReasonBadLifetime), func(f *cmdenvelope.Fields) { f.ExpiresAtNS = f.IssuedAtNS - 1 })
	bad("lifetime-over-31d", "ömür 31 gün + 1 ns", string(cmdenvelope.ReasonBadLifetime), func(f *cmdenvelope.Fields) {
		f.ExpiresAtNS = f.IssuedAtNS + int64(cmdenvelope.MaxLifetime) + 1
	})
	bad("body-device-id-mixed-case", "gövdedeki cihaz kimliği karışık harf", string(cmdenvelope.ReasonBadDeviceID), func(f *cmdenvelope.Fields) {
		f.DeviceID = "0B1c2d3e-4f50-4a61-8b72-93a4b5c6d7e8"
	})
	add("verifier-device-id-mixed-case", "doğrulayanın kendi cihaz kimliği karışık harf (kanonik küçük harf olmalı)",
		string(cmdenvelope.ReasonBadDeviceID), baseD, bp, withDevice("0B1c2d3e-4f50-4a61-8b72-93a4b5c6d7e8"))
	add("wrong-device", "başka bir cihaz için imzalanmış zarf bu cihaza teslim edildi", string(cmdenvelope.ReasonWrongDevice), baseD, bp, withDevice(Device2))
	add("body-device-id-other", "gövdedeki cihaz kimliği başka bir cihaz (geçerli imzayla bile)", string(cmdenvelope.ReasonWrongDevice),
		g.crafted(func(f *cmdenvelope.Fields) { f.DeviceID = Device2 }), bp)
	add("wire-command-id-differs", "telde command_id gövdedekinden farklı", m, baseD, bp, withWire("a1b2c3d4-e5f6-4a07-98a9-b0c1d2e3f4a6", ""))
	add("wire-type-differs", "telde tip gövdedekinden farklı (QUARANTINE→WIPE)", m, baseD, bp, withWire("", cmdenvelope.TypeWipe))
	add("wire-values-match", "telde command_id ve tip gövdeyle aynı", "ok", baseD, bp, withWire(baseEnv().CommandID, baseEnv().Type))

	// ---- negatif: params ----
	mp := string(cmdenvelope.ReasonMalformedParams)
	badParams := func(name, doc string, ps []cmdenvelope.Param) { add(name, doc, mp, baseD, ps) }
	badParams("params-nul", "param değerinde NUL", []cmdenvelope.Param{cmdenvelope.StringParam("a", "x\x00y")})
	badParams("params-duplicate-key", "yinelenen param anahtarı", []cmdenvelope.Param{cmdenvelope.StringParam("a", "1"), cmdenvelope.StringParam("a", "2")})
	badParams("params-key-uppercase", "büyük harfli param anahtarı", []cmdenvelope.Param{cmdenvelope.StringParam("Path", "1")})
	var many []cmdenvelope.Param
	for i := 0; i < 33; i++ {
		many = append(many, cmdenvelope.StringParam(fmt.Sprintf("k%02d", i), "v"))
	}
	badParams("params-33-keys", "33 param anahtarı", many)
	badParams("params-list-65-items", "65 öğeli liste", []cmdenvelope.Param{cmdenvelope.ListParam("a", make([]string, 65)...)})

	// ---- negatif: imzadan sonra kurcalama ----
	bs := string(cmdenvelope.ReasonBadSignature)
	tamper := func(name, doc string, f func(*cmdenvelope.Fields)) {
		add(name, doc, bs, g.mutPayload(baseD, f), bp)
	}
	tamper("tampered-tenant", "imzadan sonra kiracı değişti", func(f *cmdenvelope.Fields) { f.TenantID = "other" })
	tamper("type-swapped-to-wipe", "QUARANTINE zarfı WIPE'a çevrildi", func(f *cmdenvelope.Fields) { f.Type = cmdenvelope.TypeWipe })
	tamper("tampered-sequence", "sequence değişti", func(f *cmdenvelope.Fields) { f.Sequence = 9 })
	tamper("tampered-command-id", "command_id değişti (eski imzayla)", func(f *cmdenvelope.Fields) { f.CommandID = "a1b2c3d4-e5f6-4a07-98a9-b0c1d2e3f4a6" })
	tamper("tampered-requested-by", "requested_by değişti", func(f *cmdenvelope.Fields) { f.RequestedBy = "admin:other" })
	tamper("tampered-expiry", "expires_at +1 ns", func(f *cmdenvelope.Fields) { f.ExpiresAtNS++ })
	tamper("tampered-params-digest", "params özetinin tek biti değişti", func(f *cmdenvelope.Fields) { f.ParamsDigest[0] ^= 1 })
	add("tampered-wire-params", "imzadan sonra telde taşınan params değişti (özet uyuşmaz)", bs, baseD, []cmdenvelope.Param{cmdenvelope.StringParam("reason", "x")})

	// ---- negatif: anahtar ----
	add("key-role-mismatch", "anahtar KÖK rolünde; komut doğrulayamaz", string(cmdenvelope.ReasonUnknownKey), baseD, bp,
		withKeys(func() cmdenvelope.KeyEntry {
			k := cmdKey("cmdA", BaseNS-hour, BaseNS+90*day)
			k.Role = cmdenvelope.KeyRoleRoot
			return k
		}()))
	add("key-expired-before-issue", "anahtar issued_at'tan önce sona erdi", string(cmdenvelope.ReasonKeyExpired), baseD, bp,
		withKeys(cmdKey("cmdA", BaseNS-2*hour, BaseNS-1)))
	add("key-not-yet-valid-at-issue", "anahtar issued_at'tan sonra başlıyor", string(cmdenvelope.ReasonKeyExpired), baseD, bp,
		withKeys(cmdKey("cmdA", BaseNS+1, BaseNS+90*day)))
	add("key-without-expiry", "komut anahtarında not_after yok (fail-closed)", string(cmdenvelope.ReasonKeyExpired), baseD, bp,
		withKeys(cmdKey("cmdA", BaseNS-hour, 0)))

	// ---- negatif: zaman ----
	add("expired", "bitişten sonra", string(cmdenvelope.ReasonExpired), baseD, bp, withNow(baseEnv().ExpiresAtNS+1))
	add("clock-unsynced", "güvenilir saat yok (geçici)", string(cmdenvelope.ReasonClockUnsynced), baseD, bp, withNow(0))
	e = baseEnv()
	e.IssuedAtNS = BaseNS + 30*day
	e.ExpiresAtNS = e.IssuedAtNS + hour
	add("issued-in-the-future", "issued_at şimdi + 30 gün (geçici)", string(cmdenvelope.ReasonNotYetValid), g.sign("cmdA", e), e.Params,
		withKeys(cmdKey("cmdA", BaseNS-hour, BaseNS+90*day)))
	e = baseEnv()
	e.IssuedAtNS = nowOK() + int64(cmdenvelope.ClockSkew)
	e.ExpiresAtNS = e.IssuedAtNS + hour
	pos("issued-at-skew-edge", "issued_at == now + 2 dk: kabul", e)
	e.IssuedAtNS++
	e.ExpiresAtNS++
	add("issued-beyond-skew", "issued_at == now + 2 dk + 1 ns (geçici)", string(cmdenvelope.ReasonNotYetValid), g.sign("cmdA", e), e.Params)

	return out
}

// trustBody: etki alanı ayrımı vektörü için herhangi bir bildirimin kanonik baytları.
func trustBody(g *gen) []byte {
	st := cmdenvelope.Statement{
		Epoch: 1, RootThreshold: 1, IssuedAtNS: BaseNS,
		Keys: []cmdenvelope.KeyEntry{rootKey("root1"), cmdKey("cmdA", BaseNS, BaseNS+90*day)},
	}
	b, err := cmdenvelope.CanonicalStatement(st)
	g.must(err)
	return b
}

// ---- params vektörleri -------------------------------------------------------

func (g *gen) paramCases() []ParamsCase {
	var out []ParamsCase
	valid := func(name string, ps []cmdenvelope.Param) {
		enc, err := cmdenvelope.EncodeParams(ps)
		g.must(err)
		d, err := cmdenvelope.ParamsDigest(ps)
		g.must(err)
		out = append(out, ParamsCase{Name: name, Params: ParamsToJSON(ps), EncodedHex: hex.EncodeToString(enc), DigestHex: hex.EncodeToString(d[:]), Expect: "ok"})
	}
	valid("empty", nil)
	valid("one-string", []cmdenvelope.Param{cmdenvelope.StringParam("a", "x")})
	valid("one-list", []cmdenvelope.Param{cmdenvelope.ListParam("a", "x")})
	valid("string-and-list-sorted", []cmdenvelope.Param{cmdenvelope.ListParam("b", "1", "2"), cmdenvelope.StringParam("a", "x")})
	valid("empty-list", []cmdenvelope.Param{cmdenvelope.ListParam("a")})
	valid("injection-attempt", []cmdenvelope.Param{cmdenvelope.StringParam("a", `x";b="y`)})

	bad := func(name string, b []byte) {
		out = append(out, ParamsCase{Name: name, EncodedHex: hex.EncodeToString(b), Expect: string(cmdenvelope.ReasonMalformedParams)})
	}
	tagged := func(n uint32, body func(b []byte) []byte) []byte {
		b := lp(nil, cmdenvelope.DomainParamsV2)
		b = u32(b, n)
		return body(b)
	}
	str := func(b []byte, k, v string) []byte {
		b = lp(b, k)
		b = append(b, 0x01)
		return lp(b, v)
	}
	bad("unsorted-keys", tagged(2, func(b []byte) []byte { return str(str(b, "b", "1"), "a", "2") }))
	bad("duplicate-keys", tagged(2, func(b []byte) []byte { return str(str(b, "a", "1"), "a", "2") }))
	bad("trailing-byte", append(tagged(1, func(b []byte) []byte { return str(b, "a", "1") }), 0x00))
	bad("invalid-utf8-value", tagged(1, func(b []byte) []byte { return str(b, "a", "\xff\xfe") }))
	bad("nul-value", tagged(1, func(b []byte) []byte { return str(b, "a", "a\x00b") }))
	bad("unknown-type-tag", tagged(1, func(b []byte) []byte {
		b = lp(b, "a")
		b = append(b, 0x09)
		return lp(b, "v")
	}))
	bad("count-exceeds-data", tagged(2, func(b []byte) []byte { return str(b, "a", "1") }))
	bad("wrong-domain-tag", u32(lp(nil, "kut-cmd-envelope-v2"), 0))
	bad("key-uppercase", tagged(1, func(b []byte) []byte { return str(b, "Key", "1") }))
	bad("too-many-keys", tagged(33, func(b []byte) []byte { return b }))
	return out
}

func lp(b []byte, s string) []byte {
	b = append(b, byte(len(s)>>24), byte(len(s)>>16), byte(len(s)>>8), byte(len(s)))
	return append(b, s...)
}

func u32(b []byte, n uint32) []byte {
	return append(b, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func paramMapCases() []ParamMapCase {
	r := string(cmdenvelope.ReasonMalformedParams)
	return []ParamMapCase{
		{"strings-and-lists", `{"a":"x","b":["y","z"]}`, "ok"},
		{"empty-object", `{}`, "ok"},
		{"number", `{"a":1}`, r},
		{"float", `{"a":1.5}`, r},
		{"bool", `{"a":true}`, r},
		{"null", `{"a":null}`, r},
		{"nested-object", `{"a":{"b":"c"}}`, r},
		{"list-with-number", `{"a":["x",2]}`, r},
		{"list-with-null", `{"a":[null]}`, r},
		{"list-of-lists", `{"a":[["x"]]}`, r},
	}
}

// ---- güven bildirimi senaryoları ----------------------------------------------

func (g *gen) stmt(epoch uint64, threshold uint32, issued int64, keys ...cmdenvelope.KeyEntry) cmdenvelope.Statement {
	return cmdenvelope.Statement{Epoch: epoch, Keys: keys, RootThreshold: threshold, IssuedAtNS: issued}
}

func (g *gen) signedBy(st cmdenvelope.Statement, signers ...string) cmdenvelope.Statement {
	for _, s := range signers {
		var err error
		st, err = cmdenvelope.SignStatement(priv(s), st)
		g.must(err)
	}
	return st
}

func (g *gen) dsse(st cmdenvelope.Statement) cmdenvelope.DSSE {
	d, err := st.DSSE()
	g.must(err)
	return d
}

// custom, bildirim gövdesine özel imza listesiyle bir DSSE zarfı kurar.
func (g *gen) custom(st cmdenvelope.Statement, payloadType string, sigs ...cmdenvelope.DSSESignature) cmdenvelope.DSSE {
	body, err := cmdenvelope.CanonicalStatement(st)
	g.must(err)
	return cmdenvelope.DSSE{PayloadType: payloadType, Payload: body, Signatures: sigs}
}

func (g *gen) step(name, doc, expect, mode string, jump bool, epochAfter uint64, now int64, d cmdenvelope.DSSE) StepCase {
	c := StepCase{Name: name, Doc: doc, NowNS: now, DSSE: DSSEToJSON(d), PayloadHex: hex.EncodeToString(d.Payload),
		Expect: expect, Mode: mode, EpochJump: jump, EpochAfter: epochAfter}
	if st, err := cmdenvelope.ParseStatement(d.Payload); err == nil {
		b := StatementToJSON(st)
		c.Body = &b
	}
	return c
}

func (g *gen) scenarios() []ScenarioCase {
	var out []ScenarioCase
	end := BaseNS + 90*day
	nowS := BaseNS + 30*hour
	roots3 := func() []cmdenvelope.KeyEntry {
		return []cmdenvelope.KeyEntry{rootKey("root1"), rootKey("root2"), rootKey("root3")}
	}
	with := func(base []cmdenvelope.KeyEntry, more ...cmdenvelope.KeyEntry) []cmdenvelope.KeyEntry {
		return append(append([]cmdenvelope.KeyEntry(nil), base...), more...)
	}
	cmdA := cmdKey("cmdA", BaseNS, end)
	cmdB := cmdKey("cmdB", BaseNS, end)
	sig := func(name string, st cmdenvelope.Statement) cmdenvelope.DSSESignature {
		body, err := cmdenvelope.CanonicalStatement(st)
		g.must(err)
		return g.rawSig(name, cmdenvelope.PayloadTypeTrust, body)
	}

	// --- A: genesis → rotasyon → kaldırma, ret vakaları, kök değişimi ---
	t1, t2, t3, t4 := BaseNS+hour, BaseNS+2*hour, BaseNS+3*hour, BaseNS+4*hour
	s1 := g.signedBy(g.stmt(1, 2, t1, with(roots3(), cmdA)...), "root1", "root2")
	s2 := g.signedBy(g.stmt(2, 2, t2, with(roots3(), cmdA, cmdB)...), "root1", "root3")
	s3 := g.signedBy(g.stmt(3, 2, t3, with(roots3(), cmdB)...), "root2", "root3")
	newRoots := []cmdenvelope.KeyEntry{rootKey("root1"), rootKey("root4"), rootKey("root5")}
	s4ok := g.signedBy(g.stmt(4, 2, t4, with(newRoots, cmdB)...), "root1", "root2", "root4")
	a := ScenarioCase{Name: "genesis-rotation-removal", Doc: "pin yok; bootstrap genesis, zincir halkaları, ret vakaları ve kök değişimi"}
	a.Steps = []StepCase{
		g.step("genesis", "epoch 1, 3 kök eşik 2, r1+r2 imzalı: kendi eşiğiyle tutarlı → bootstrap", "ok", "bootstrap", false, 1, nowS, g.dsse(s1)),
		g.step("rotation-add-cmdB", "epoch 2: cmdB eklenir, r1+r3 imzalı", "ok", "chain", false, 2, nowS, g.dsse(s2)),
		g.step("replay-epoch-2", "epoch 2 yeniden sunulur", "stale_epoch", "", false, 2, nowS, g.dsse(s2)),
		g.step("old-epoch-1", "epoch 1 yeniden sunulur", "stale_epoch", "", false, 2, nowS, g.dsse(s1)),
		g.step("threshold-not-met", "epoch 3 yalnız r1 imzalı (eşik 2)", "threshold_not_met", "", false, 2, nowS,
			g.dsse(g.signedBy(g.stmt(3, 2, t3, with(roots3(), cmdB)...), "root1"))),
		g.step("duplicate-keyid-counts-once", "epoch 3 r1 iki kez imzalı: aynı keyid bir kez sayılır", "threshold_not_met", "", false, 2, nowS,
			func() cmdenvelope.DSSE {
				st := g.signedBy(g.stmt(3, 2, t3, with(roots3(), cmdB)...), "root1")
				st.Signatures = append(st.Signatures, st.Signatures[0])
				return g.dsse(st)
			}()),
		g.step("command-key-signs-statement", "epoch 3 yalnız komut anahtarı imzalı", "signer_not_root", "", false, 2, nowS,
			g.dsse(g.signedBy(g.stmt(3, 2, t3, with(roots3(), cmdB)...), "cmdB"))),
		g.step("forged-signature", "epoch 3: r1 geçerli, r2 imzasının tek biti bozuk", "threshold_not_met", "", false, 2, nowS,
			func() cmdenvelope.DSSE {
				st := g.signedBy(g.stmt(3, 2, t3, with(roots3(), cmdB)...), "root1", "root2")
				st.Signatures[1].Sig = append([]byte(nil), st.Signatures[1].Sig...)
				st.Signatures[1].Sig[0] ^= 1
				return g.dsse(st)
			}()),
		g.step("skipped-epoch-without-pin", "epoch 5, pin imzası yok", "epoch_skipped", "", false, 2, nowS,
			g.dsse(g.signedBy(g.stmt(5, 2, t4, with(roots3(), cmdB)...), "root1", "root2"))),
		g.step("removal-of-cmdA", "epoch 3: cmdA kaldırılır, r2+r3 imzalı", "ok", "chain", false, 3, nowS, g.dsse(s3)),
		g.step("root-change-missing-new-quorum", "epoch 4: kök kümesi {r1,r4,r5}; yalnız eski eşik (r1,r2) imzaladı", "threshold_not_met", "", false, 3, nowS,
			g.dsse(g.signedBy(g.stmt(4, 2, t4, with(newRoots, cmdB)...), "root1", "root2"))),
		g.step("root-change-missing-old-quorum", "epoch 4: yeni küme eşiği (r1,r4) var, eski kümeden yalnız r1", "threshold_not_met", "", false, 3, nowS,
			g.dsse(g.signedBy(g.stmt(4, 2, t4, with(newRoots, cmdB)...), "root1", "root4"))),
		g.step("root-change-both-quorums", "epoch 4: eski (r1,r2) ve yeni (r1,r4) eşik imzaladı", "ok", "chain", false, 4, nowS, g.dsse(s4ok)),
	}
	a.KeyChecks = []KeyCheckCase{
		{"cmdB-valid", idOf("cmdB"), nowS, "ok"},
		{"cmdA-removed", idOf("cmdA"), nowS, "key_not_in_chain"},
		{"root-key-is-not-a-command-key", idOf("root1"), nowS, "key_not_in_chain"},
		{"cmdB-after-expiry", idOf("cmdB"), end + 1, "key_expired"},
		{"clock-unsynced", idOf("cmdB"), 0, "clock_unsynced"},
	}
	a.ChainChecks = []ChainCheckCase{
		{"full-chain-1-2-3", []string{"genesis", "rotation-add-cmdB", "removal-of-cmdA"}, nowS, "ok"},
		{"full-chain-with-root-change", []string{"genesis", "rotation-add-cmdB", "removal-of-cmdA", "root-change-both-quorums"}, nowS, "ok"},
		{"missing-genesis", []string{"rotation-add-cmdB", "removal-of-cmdA"}, nowS, "chain_incomplete"},
		{"missing-middle-epoch", []string{"genesis", "removal-of-cmdA"}, nowS, "chain_incomplete"},
		{"invalid-hop", []string{"genesis", "rotation-add-cmdB", "threshold-not-met"}, nowS, "threshold_not_met"},
		{"empty", nil, nowS, "chain_incomplete"},
	}
	out = append(out, a)

	// --- B: pin ile imzalı genesis, zincir, epoch atlaması ---
	pinHex := []string{hex.EncodeToString(pub("root1"))}
	p1 := g.signedBy(g.stmt(1, 2, t1, with(roots3(), cmdA)...), "root1")
	p2 := g.signedBy(g.stmt(2, 2, t2, with(roots3(), cmdA, cmdB)...), "root2", "root3")
	jumpKeys := []cmdenvelope.KeyEntry{rootKey("root4"), cmdKey("cmdB", BaseNS, end)}
	p9 := g.signedBy(g.stmt(9, 1, t3, jumpKeys...), "root1")
	b := ScenarioCase{Name: "pin-signed-jump", Doc: "pin = root1; pin imzası tek başına yeter ve epoch atlatır", PinsHex: pinHex}
	b.Steps = []StepCase{
		g.step("self-signed-genesis-when-pinned", "pin tanımlıyken kendinden imzalı genesis reddedilir", "pin_required", "", false, 0, nowS,
			g.dsse(g.signedBy(g.stmt(1, 2, t1, with(roots3(), cmdA)...), "root2", "root3"))),
		g.step("pin-signed-genesis", "tek pin imzası yeter (eşik aranmaz)", "ok", "pin", false, 1, nowS, g.dsse(p1)),
		g.step("chain-hop-without-pin", "epoch 2: pin imzasız, mevcut eşik (r2,r3)", "ok", "chain", false, 2, nowS, g.dsse(p2)),
		g.step("jump-without-pin", "epoch 12 pin imzasız (r2,r3)", "epoch_skipped", "", false, 2, nowS,
			g.dsse(g.signedBy(g.stmt(12, 2, t3, with(roots3(), cmdB)...), "root2", "root3"))),
		g.step("pin-signed-jump-to-9", "epoch 2 → 9 pin imzasıyla; kök kümesi bile değişebilir", "ok", "pin", true, 9, nowS, g.dsse(p9)),
		g.step("pin-cannot-go-back", "pin imzası da epoch geriletemez", "stale_epoch", "", false, 9, nowS,
			g.dsse(g.signedBy(g.stmt(5, 1, t3, jumpKeys...), "root1"))),
		g.step("old-root-quorum-no-longer-works", "kök kümesi {root4}: eski r2,r3 imzalı epoch 10 reddedilir", "threshold_not_met", "", false, 9, nowS,
			g.dsse(g.signedBy(g.stmt(10, 1, t4, jumpKeys...), "root2", "root3"))),
	}
	b.KeyChecks = []KeyCheckCase{{"cmdB-valid-after-jump", idOf("cmdB"), nowS, "ok"}, {"cmdA-gone-after-jump", idOf("cmdA"), nowS, "key_not_in_chain"}}
	out = append(out, b)

	// --- C: süresi dolmuş anahtarlar ---
	r2short := rootKey("root2")
	r2short.NotAfterNS = BaseNS + 30*int64(time.Minute)
	cmdShort := cmdKey("cmdA", BaseNS, BaseNS+10*hour)
	keysC := with([]cmdenvelope.KeyEntry{rootKey("root1"), r2short, rootKey("root3")}, cmdShort)
	genExpiredSigner := g.signedBy(g.stmt(1, 2, t1, keysC...), "root1", "root2")
	early := BaseNS + 10*int64(time.Minute)
	genOK := g.signedBy(g.stmt(1, 2, early, keysC...), "root1", "root2")
	hop2Bad := g.signedBy(g.stmt(2, 2, t2, keysC...), "root1", "root2")
	hop2OK := g.signedBy(g.stmt(2, 2, t2, keysC...), "root1", "root3")
	c := ScenarioCase{Name: "expired-keys", Doc: "kök imzacı penceresi bildirimin issued_at anında değerlendirilir; komut anahtarı süresi zincirde denetlenir"}
	c.Steps = []StepCase{
		g.step("genesis-signed-by-expired-root", "genesis issued=base+1h, root2 base+30dk'da sona erdi → eşik sağlanmaz", "threshold_not_met", "", false, 0, nowS, g.dsse(genExpiredSigner)),
		g.step("genesis-signed-inside-window", "genesis issued=base+10dk, root2 penceresi içinde", "ok", "bootstrap", false, 1, nowS, g.dsse(genOK)),
		g.step("hop-signed-by-expired-root", "epoch 2 issued=base+2h: root2 artık geçersiz, tek geçerli imza r1", "threshold_not_met", "", false, 1, nowS, g.dsse(hop2Bad)),
		g.step("hop-signed-by-valid-roots", "epoch 2: r1+r3", "ok", "chain", false, 2, nowS, g.dsse(hop2OK)),
	}
	c.KeyChecks = []KeyCheckCase{
		{"cmdA-inside-window", idOf("cmdA"), BaseNS + 5*hour, "ok"},
		{"cmdA-expired", idOf("cmdA"), BaseNS + 11*hour, "key_expired"},
		{"cmdA-before-not-before", idOf("cmdA"), BaseNS - 1, "not_yet_valid"},
	}
	out = append(out, c)

	// --- D: tek kök, eşik 1 ---
	d := ScenarioCase{Name: "single-root-small-deployment", Doc: "1-of-1 kök; bootstrap yalnız kendi eşiğiyle"}
	d.Steps = []StepCase{
		g.step("genesis-one-of-one", "tek kök kendi bildirimini imzalar", "ok", "bootstrap", false, 1, nowS,
			g.dsse(g.signedBy(g.stmt(1, 1, t1, rootKey("root1"), cmdA), "root1"))),
	}
	out = append(out, d)

	// --- E: DSSE'ye özgü imza işleme ---
	gen1 := g.stmt(1, 2, t1, with(roots3(), cmdA)...)
	body1, err := cmdenvelope.CanonicalStatement(gen1)
	g.must(err)
	rawSig := func(name string) cmdenvelope.DSSESignature {
		return cmdenvelope.DSSESignature{KeyID: idOf(name), Sig: ed25519.Sign(priv(name), body1)}
	}
	validDSSE := g.dsse(g.signedBy(gen1, "root1", "root2"))
	nine := g.custom(gen1, cmdenvelope.PayloadTypeTrust)
	for i := 0; i < 9; i++ {
		nine.Signatures = append(nine.Signatures, sig("root1", gen1))
	}
	hint := g.custom(gen1, cmdenvelope.PayloadTypeTrust, sig("root1", gen1),
		cmdenvelope.DSSESignature{KeyID: idOf("root3"), Sig: sig("root2", gen1).Sig})
	e := ScenarioCase{Name: "dsse-signature-handling", Doc: "yük türü, PAE, keyid ipucu, yinelenen keyid ve bilinmeyen imzacı"}
	wrongType := validDSSE
	wrongType.PayloadType = cmdenvelope.PayloadTypeCommand
	oldType := validDSSE
	oldType.PayloadType = "application/vnd.kut.trust.v1"
	withEvil := validDSSE
	withEvil.Signatures = append(append([]cmdenvelope.DSSESignature(nil), validDSSE.Signatures...), sig("evil", gen1))
	e.Steps = []StepCase{
		g.step("wrong-payload-type", "doğru imzalar ama yük türü komut zarfı türü", "bad_payload_type", "", false, 0, nowS, wrongType),
		g.step("unsupported-payload-version", "yük türü trust.v1", "unsupported_version", "", false, 0, nowS, oldType),
		g.step("signatures-over-body-without-pae", "r1+r2 imzaları PAE olmadan doğrudan gövde üzerinde", "threshold_not_met", "", false, 0, nowS,
			g.custom(gen1, cmdenvelope.PayloadTypeTrust, rawSig("root1"), rawSig("root2"))),
		g.step("signatures-under-command-payload-type", "r1+r2 imzaları komut yük türüyle atılmış", "threshold_not_met", "", false, 0, nowS,
			g.custom(gen1, cmdenvelope.PayloadTypeTrust, g.rawSig("root1", cmdenvelope.PayloadTypeCommand, body1), g.rawSig("root2", cmdenvelope.PayloadTypeCommand, body1))),
		g.step("keyid-hint-points-at-other-root", "r2 imzası r3 keyid'siyle sunuldu: r3 anahtarıyla doğrulanamaz", "threshold_not_met", "", false, 0, nowS, hint),
		g.step("duplicate-keyid-counts-once", "aynı keyid iki kez (eşik 2)", "threshold_not_met", "", false, 0, nowS,
			g.custom(gen1, cmdenvelope.PayloadTypeTrust, sig("root1", gen1), sig("root1", gen1))),
		g.step("nine-signature-entries", "9 imza girdisi (sınır 8)", "malformed_statement", "", false, 0, nowS, nine),
		g.step("no-signatures", "imzasız zarf", "malformed_statement", "", false, 0, nowS, g.custom(gen1, cmdenvelope.PayloadTypeTrust)),
		g.step("unknown-extra-signer-ignored", "geçerli r1+r2 yanında bilinmeyen üçüncü imzacı yok sayılır", "ok", "bootstrap", false, 1, nowS, withEvil),
	}
	out = append(out, e)
	return out
}
