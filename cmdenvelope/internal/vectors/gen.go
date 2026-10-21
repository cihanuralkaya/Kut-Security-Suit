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
		Description: "kut-cmd-envelope-v2 / kut-cmd-trust-v2 altın vektörleri. Tohumlar sabittir; " +
			"imzalar deterministiktir. Sunucu ve ajan testleri bu dosyayı aynen okur.",
	}
	for _, n := range seedNames {
		seed := sha256.Sum256([]byte("kut-w2-vector-seed:" + n))
		f.Seeds = append(f.Seeds, SeedJSON{Name: n, SeedHex: hex.EncodeToString(seed[:]), PubHex: hex.EncodeToString(pub(n)), KeyID: idOf(n)})
	}
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

// ---- zarf vektörleri ---------------------------------------------------------

func baseEnv() cmdenvelope.Envelope {
	return cmdenvelope.Envelope{
		CommandID: "a1b2c3d4-e5f6-4a07-98a9-b0c1d2e3f4a5", TenantID: "", Type: cmdenvelope.TypeQuarantine,
		RequestedBy: "admin:9f8e7d6c-5b4a-4392-8180-706f5e4d3c2b",
		Sequence:    0, Nonce: "00112233445566778899aabbccddeeff",
		IssuedAtNS: BaseNS, ExpiresAtNS: BaseNS + 7*day,
	}
}

// cmdAWindow: cmdA, BaseNS-1h .. BaseNS+90d.
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
func withKeys(ks ...cmdenvelope.KeyEntry) envOpt {
	return func(c *EnvelopeCase) {
		c.Keys = nil
		for _, k := range ks {
			c.Keys = append(c.Keys, KeyToJSON(k))
		}
	}
}

// addCase, bir zarf vektörü ekler. CanonicalHex/özetler, kanonik bayt kurulabiliyorsa
// (zarf alanları geçerliyse) doldurulur.
func (g *gen) addCase(out *[]EnvelopeCase, name, doc, expect string, env cmdenvelope.Envelope, opts ...envOpt) {
	c := EnvelopeCase{
		Name: name, Doc: doc, DeviceID: Device, NowNS: nowOK(), Expect: expect,
		Envelope: EnvelopeToJSON(env),
	}
	withKeys(trustedKeys("cmdA")...)(&c)
	for _, o := range opts {
		o(&c)
	}
	if msg, err := cmdenvelope.CanonicalV2(Device, env); err == nil {
		c.CanonicalHex = hex.EncodeToString(msg)
		sum := sha256.Sum256(msg)
		c.DigestHex = hex.EncodeToString(sum[:])
		if d, err := cmdenvelope.ParamsDigest(env.Params); err == nil {
			c.ParamsDigestHex = hex.EncodeToString(d[:])
		}
	}
	*out = append(*out, c)
}

func (g *gen) sign(name string, env cmdenvelope.Envelope) cmdenvelope.Envelope {
	s, err := cmdenvelope.SignV2(priv(name), Device, env)
	g.must(err)
	return s
}

func (g *gen) cosign(name string, env cmdenvelope.Envelope) cmdenvelope.Signature {
	s, err := cmdenvelope.CoSignV2(priv(name), Device, env)
	g.must(err)
	return s
}

func longStr(c byte, n int) string { return strings.Repeat(string(c), n) }

func (g *gen) envelopes() []EnvelopeCase {
	var out []EnvelopeCase
	add := func(name, doc, expect string, env cmdenvelope.Envelope, opts ...envOpt) {
		g.addCase(&out, name, doc, expect, env, opts...)
	}

	// ---- pozitif ----
	base := baseEnv()
	add("baseline-quarantine", "en küçük geçerli zarf: sequence 0, boş kiracı, boş params", "ok", g.sign("cmdA", base))

	e := baseEnv()
	e.Sequence, e.TenantID, e.CorrelationID = 0x0102030405060708, "acme", "req-0001"
	e.Params = []cmdenvelope.Param{cmdenvelope.StringParam("reason", "ransomware")}
	add("nonzero-sequence", "sequence 8 bayt büyük-endian (2^32 üzeri)", "ok", g.sign("cmdA", e))

	e = baseEnv()
	e.Sequence = ^uint64(0)
	add("max-sequence", "uint64 üst sınır", "ok", g.sign("cmdA", e))

	e = baseEnv()
	e.TenantID = "acme"
	prim := g.sign("cmdA", e)
	prim.ExtraSignatures = []cmdenvelope.Signature{g.cosign("cmdB", prim)}
	add("extra-signatures-both-trusted", "birincil cmdA + ek cmdB; ajan ikisine de güveniyor", "ok", prim, withKeys(trustedKeys("cmdA", "cmdB")...))
	add("extra-signature-secondary-only", "aynı zarf; ajan yalnız cmdB'ye güveniyor (rotasyon örtüşmesi)", "ok", prim, withKeys(trustedKeys("cmdB")...))
	add("extra-signature-primary-only", "aynı zarf; ajan yalnız cmdA'ya güveniyor", "ok", prim, withKeys(trustedKeys("cmdA")...))
	unk := g.sign("cmdA", e)
	unk.ExtraSignatures = []cmdenvelope.Signature{g.cosign("evil", unk)}
	add("extra-signature-unknown-ignored", "bilinmeyen ek imza yok sayılır, ortak imza yeter", "ok", unk)

	classes := []struct {
		typ, doc string
		mod      func(*cmdenvelope.Envelope)
	}{
		{cmdenvelope.TypeQuarantine, "izolasyon", func(e *cmdenvelope.Envelope) {
			e.Params = []cmdenvelope.Param{cmdenvelope.StringParam("reason", "ransomware")}
		}},
		{cmdenvelope.TypeUnquarantine, "izolasyon kaldırma", func(e *cmdenvelope.Envelope) {
			e.Sequence = 2
		}},
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
		add("type-"+strings.ToLower(c.typ), c.doc, "ok", g.sign("cmdA", e))
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
	add("unicode-params", "unicode değerler, boş dize, boş liste, liste sırası korunur", "ok", g.sign("cmdA", e))

	e = baseEnv()
	for i := 0; i < cmdenvelope.MaxParamKeys; i++ {
		e.Params = append(e.Params, cmdenvelope.StringParam(fmt.Sprintf("k%02d", 31-i), fmt.Sprintf("v%d", i)))
	}
	add("max-params-32-keys", "32 anahtar, ters sırada verildi (özet sıralıdır)", "ok", g.sign("cmdA", e))

	e = baseEnv()
	e.ExpiresAtNS = e.IssuedAtNS + int64(cmdenvelope.MaxLifetime)
	add("lifetime-exactly-31d", "ömür tam 31 gün", "ok", g.sign("cmdA", e))

	e = baseEnv()
	e.IssuedAtNS = BaseNS + 90*day
	e.ExpiresAtNS = e.IssuedAtNS + hour
	add("key-window-upper-edge", "issued_at == key.not_after: kabul", "ok", g.sign("cmdA", e),
		withNow(e.IssuedAtNS+int64(time.Minute)), withKeys(cmdKey("cmdA", BaseNS-hour, e.IssuedAtNS)))

	e = baseEnv()
	e.CorrelationID, e.RequestedBy, e.ApprovedBy, e.TenantID = longStr('c', 128), longStr('r', 128), longStr('p', 128), longStr('t', 63)
	add("principal-limits-max", "requested_by/approved_by/correlation 128, tenant 63 bayt", "ok", g.sign("cmdA", e))

	e = baseEnv()
	at := BaseNS + hour
	add("key-expired-after-issue-still-valid", "anahtar issued_at'ta geçerliydi; teslim anında dolmuş olsa da kabul",
		"ok", g.sign("cmdA", e), withNow(at), withKeys(cmdKey("cmdA", BaseNS-hour, BaseNS+hour/2)))

	// ---- negatif: sürüm ----
	signed := g.sign("cmdA", baseEnv())
	for _, v := range []uint32{0, 1, 3} {
		x := signed
		x.Version = v
		add(fmt.Sprintf("version-%d", v), "envelope_version 2 dışı", string(cmdenvelope.ReasonUnsupportedVersion), x)
	}

	// ---- negatif: alan sınırları (imza değişmeden alan bozulur) ----
	mut := func(name, doc string, reason cmdenvelope.Reason, f func(*cmdenvelope.Envelope), opts ...envOpt) {
		x := signed
		f(&x)
		add(name, doc, string(reason), x, opts...)
	}
	m := cmdenvelope.ReasonMalformedEnvelope
	mut("command-id-uppercase", "büyük harfli UUID (dedup takma adı)", m, func(x *cmdenvelope.Envelope) { x.CommandID = strings.ToUpper(x.CommandID) })
	mut("command-id-braces", "süslü parantezli UUID", m, func(x *cmdenvelope.Envelope) { x.CommandID = "{" + x.CommandID + "}" })
	mut("command-id-no-hyphens", "tiresiz UUID", m, func(x *cmdenvelope.Envelope) { x.CommandID = strings.ReplaceAll(x.CommandID, "-", "") })
	mut("command-id-not-v4", "sürüm 1 UUID", m, func(x *cmdenvelope.Envelope) { x.CommandID = "a1b2c3d4-e5f6-1a07-98a9-b0c1d2e3f4a5" })
	mut("nonce-uppercase-hex", "nonce büyük harfli hex", m, func(x *cmdenvelope.Envelope) { x.Nonce = strings.ToUpper("aabbccddeeff00112233445566778899") })
	mut("nonce-31-chars", "nonce 31 karakter", m, func(x *cmdenvelope.Envelope) { x.Nonce = x.Nonce[:31] })
	mut("key-id-64-bit", "64-bit (16 hex) anahtar kimliği", m, func(x *cmdenvelope.Envelope) { x.KeyID = x.KeyID[:16] })
	mut("key-id-uppercase", "büyük harfli anahtar kimliği", m, func(x *cmdenvelope.Envelope) { x.KeyID = strings.ToUpper(x.KeyID) })
	mut("correlation-id-nul", "correlation_id içinde NUL", m, func(x *cmdenvelope.Envelope) { x.CorrelationID = "req\x0001" })
	mut("correlation-id-overlong", "correlation_id 129 bayt", m, func(x *cmdenvelope.Envelope) { x.CorrelationID = longStr('c', 129) })
	mut("tenant-id-space", "tenant_id içinde boşluk", m, func(x *cmdenvelope.Envelope) { x.TenantID = "ac me" })
	mut("tenant-id-overlong", "tenant_id 64 bayt", m, func(x *cmdenvelope.Envelope) { x.TenantID = longStr('t', 64) })
	mut("requested-by-0x1f", "requested_by içinde 0x1f", m, func(x *cmdenvelope.Envelope) { x.RequestedBy = "admin:a\x1fb" })
	mut("requested-by-empty", "requested_by boş", m, func(x *cmdenvelope.Envelope) { x.RequestedBy = "" })
	mut("approved-by-equals-requested", "approved_by == requested_by", m, func(x *cmdenvelope.Envelope) { x.ApprovedBy = x.RequestedBy })
	mut("signature-empty", "v2 zarf imzasız", m, func(x *cmdenvelope.Envelope) { x.Signature = nil })
	mut("signature-63-bytes", "imza 63 bayt", m, func(x *cmdenvelope.Envelope) { x.Signature = x.Signature[:63] })
	mut("extra-signature-duplicate", "aynı anahtardan iki ek imza", m, func(x *cmdenvelope.Envelope) {
		s := cmdenvelope.Signature{KeyID: idOf("cmdB"), Sig: x.Signature}
		x.ExtraSignatures = []cmdenvelope.Signature{s, s}
	})
	mut("extra-signature-short", "ek imza 10 bayt", m, func(x *cmdenvelope.Envelope) {
		x.ExtraSignatures = []cmdenvelope.Signature{{KeyID: idOf("cmdB"), Sig: x.Signature[:10]}}
	})
	mut("extra-signature-same-key-as-primary", "ek imza birincil anahtarla aynı", m, func(x *cmdenvelope.Envelope) {
		x.ExtraSignatures = []cmdenvelope.Signature{{KeyID: x.KeyID, Sig: x.Signature}}
	})
	add("device-id-mixed-case", "doğrulayanın cihaz kimliği karışık harf (kanonik küçük harf olmalı)",
		string(cmdenvelope.ReasonBadDeviceID), signed, withDevice("0B1c2d3e-4f50-4a61-8b72-93a4b5c6d7e8"))

	mut("type-empty", "tip boş (UNSPECIFIED eşleniği)", cmdenvelope.ReasonUnknownType, func(x *cmdenvelope.Envelope) { x.Type = "" })
	mut("type-unknown", "bilinmeyen tip", cmdenvelope.ReasonUnknownType, func(x *cmdenvelope.Envelope) { x.Type = "REBOOT" })
	mut("type-lowercase", "küçük harfli tip", cmdenvelope.ReasonUnknownType, func(x *cmdenvelope.Envelope) { x.Type = "quarantine" })

	mp := cmdenvelope.ReasonMalformedParams
	mut("params-nul", "param değerinde NUL", mp, func(x *cmdenvelope.Envelope) {
		x.Params = []cmdenvelope.Param{cmdenvelope.StringParam("a", "x\x00y")}
	})
	mut("params-duplicate-key", "yinelenen param anahtarı", mp, func(x *cmdenvelope.Envelope) {
		x.Params = []cmdenvelope.Param{cmdenvelope.StringParam("a", "1"), cmdenvelope.StringParam("a", "2")}
	})
	mut("params-key-uppercase", "büyük harfli param anahtarı", mp, func(x *cmdenvelope.Envelope) {
		x.Params = []cmdenvelope.Param{cmdenvelope.StringParam("Path", "1")}
	})
	mut("params-33-keys", "33 param anahtarı", mp, func(x *cmdenvelope.Envelope) {
		x.Params = nil
		for i := 0; i < 33; i++ {
			x.Params = append(x.Params, cmdenvelope.StringParam(fmt.Sprintf("k%02d", i), "v"))
		}
	})
	mut("params-list-65-items", "65 öğeli liste", mp, func(x *cmdenvelope.Envelope) {
		x.Params = []cmdenvelope.Param{cmdenvelope.ListParam("a", make([]string, 65)...)}
	})

	bl := cmdenvelope.ReasonBadLifetime
	mut("lifetime-zero", "expires == issued", bl, func(x *cmdenvelope.Envelope) { x.ExpiresAtNS = x.IssuedAtNS })
	mut("lifetime-negative", "expires < issued", bl, func(x *cmdenvelope.Envelope) { x.ExpiresAtNS = x.IssuedAtNS - 1 })
	mut("lifetime-over-31d", "ömür 31 gün + 1 ns", bl, func(x *cmdenvelope.Envelope) { x.ExpiresAtNS = x.IssuedAtNS + int64(cmdenvelope.MaxLifetime) + 1 })

	// ---- negatif: imza ----
	bs := cmdenvelope.ReasonBadSignature
	mut("tampered-param", "imzadan sonra param değeri değişti", bs, func(x *cmdenvelope.Envelope) {
		x.Params = []cmdenvelope.Param{cmdenvelope.StringParam("reason", "x")}
	})
	mut("tampered-tenant", "imzadan sonra kiracı değişti", bs, func(x *cmdenvelope.Envelope) { x.TenantID = "other" })
	mut("type-swapped-to-wipe", "QUARANTINE zarfı WIPE'a çevrildi", bs, func(x *cmdenvelope.Envelope) { x.Type = cmdenvelope.TypeWipe })
	mut("tampered-sequence", "sequence değişti", bs, func(x *cmdenvelope.Envelope) { x.Sequence = 9 })
	mut("tampered-command-id", "command_id değişti (eski imzayla)", bs, func(x *cmdenvelope.Envelope) { x.CommandID = "a1b2c3d4-e5f6-4a07-98a9-b0c1d2e3f4a6" })
	mut("tampered-requested-by", "requested_by değişti", bs, func(x *cmdenvelope.Envelope) { x.RequestedBy = "admin:other" })
	mut("tampered-expiry", "expires_at +1 ns", bs, func(x *cmdenvelope.Envelope) { x.ExpiresAtNS++ })
	mut("key-id-swapped-to-other-known-key", "key_id başka bilinen anahtara çevrildi", bs, func(x *cmdenvelope.Envelope) { x.KeyID = idOf("cmdB") },
		withKeys(trustedKeys("cmdA", "cmdB")...))
	add("wrong-device", "başka bir cihaz için imzalanmış zarf bu cihaza teslim edildi", string(bs), signed, withDevice(Device2))
	v1 := cmdenvelope.CanonicalBytes(signed.CommandID, Device, signed.Type, signed.RequestedBy, nil, signed.Nonce, signed.IssuedAtNS, signed.ExpiresAtNS)
	x := signed
	x.Signature = ed25519.Sign(priv("cmdA"), v1)
	add("v1-signature-presented-as-v2", "v1 kanonik baytları üzerindeki imza v2 olarak sunuldu", string(bs), x)
	stmt := tStatementBytes(g)
	x = signed
	x.Signature = ed25519.Sign(priv("cmdA"), stmt)
	add("trust-statement-signature-presented-as-envelope", "bildirim baytları üzerindeki imza zarf olarak sunuldu", string(bs), x)

	// ---- negatif: anahtar ----
	mut("unknown-key-id", "bilinmeyen anahtar kimliği (geçici: bildirim henüz gelmedi)", cmdenvelope.ReasonUnknownKey, func(x *cmdenvelope.Envelope) {
		x.KeyID = idOf("evil")
	})
	add("key-role-mismatch", "anahtar KÖK rolünde; komut doğrulayamaz", string(cmdenvelope.ReasonUnknownKey), signed,
		withKeys(func() cmdenvelope.KeyEntry {
			k := cmdKey("cmdA", BaseNS-hour, BaseNS+90*day)
			k.Role = cmdenvelope.KeyRoleRoot
			return k
		}()))
	add("key-expired-before-issue", "anahtar issued_at'tan önce sona erdi", string(cmdenvelope.ReasonKeyExpired), signed,
		withKeys(cmdKey("cmdA", BaseNS-2*hour, BaseNS-1)))
	add("key-not-yet-valid-at-issue", "anahtar issued_at'tan sonra başlıyor", string(cmdenvelope.ReasonKeyExpired), signed,
		withKeys(cmdKey("cmdA", BaseNS+1, BaseNS+90*day)))
	add("key-without-expiry", "komut anahtarında not_after yok (fail-closed)", string(cmdenvelope.ReasonKeyExpired), signed,
		withKeys(cmdKey("cmdA", BaseNS-hour, 0)))

	// ---- negatif: zaman ----
	add("expired", "bitişten sonra", string(cmdenvelope.ReasonExpired), signed, withNow(signed.ExpiresAtNS+1))
	add("clock-unsynced", "güvenilir saat yok (geçici)", string(cmdenvelope.ReasonClockUnsynced), signed, withNow(0))
	e = baseEnv()
	e.IssuedAtNS = BaseNS + 30*day
	e.ExpiresAtNS = e.IssuedAtNS + hour
	add("issued-in-the-future", "issued_at şimdi + 30 gün (geçici)", string(cmdenvelope.ReasonNotYetValid), g.sign("cmdA", e),
		withKeys(cmdKey("cmdA", BaseNS-hour, BaseNS+90*day)))
	e = baseEnv()
	e.IssuedAtNS = nowOK() + int64(cmdenvelope.ClockSkew)
	e.ExpiresAtNS = e.IssuedAtNS + hour
	add("issued-at-skew-edge", "issued_at == now + 2 dk: kabul", "ok", g.sign("cmdA", e))
	e.IssuedAtNS++
	e.ExpiresAtNS++
	add("issued-beyond-skew", "issued_at == now + 2 dk + 1 ns (geçici)", string(cmdenvelope.ReasonNotYetValid), g.sign("cmdA", e))

	return out
}

// tStatementBytes: etki alanı ayrımı vektörü için herhangi bir bildirimin kanonik baytları.
func tStatementBytes(g *gen) []byte {
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
		pj := []ParamJSON{}
		for _, p := range ps {
			pj = append(pj, ParamJSON{Key: p.Key, Value: p.Value, List: p.List, IsList: p.IsList})
		}
		out = append(out, ParamsCase{Name: name, Params: pj, EncodedHex: hex.EncodeToString(enc), DigestHex: hex.EncodeToString(d[:]), Expect: "ok"})
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

func (g *gen) step(name, doc, expect, mode string, jump bool, epochAfter uint64, now int64, st cmdenvelope.Statement) StepCase {
	c := StepCase{Name: name, Doc: doc, NowNS: now, Statement: StatementToJSON(st), Expect: expect, Mode: mode, EpochJump: jump, EpochAfter: epochAfter}
	if msg, err := cmdenvelope.CanonicalStatement(st); err == nil {
		c.CanonicalHex = hex.EncodeToString(msg)
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

	// --- A: genesis → rotasyon → kaldırma, ret vakaları, kök değişimi ---
	t1, t2, t3, t4 := BaseNS+hour, BaseNS+2*hour, BaseNS+3*hour, BaseNS+4*hour
	s1 := g.signedBy(g.stmt(1, 2, t1, with(roots3(), cmdA)...), "root1", "root2")
	s2 := g.signedBy(g.stmt(2, 2, t2, with(roots3(), cmdA, cmdB)...), "root1", "root3")
	s3 := g.signedBy(g.stmt(3, 2, t3, with(roots3(), cmdB)...), "root2", "root3")
	newRoots := []cmdenvelope.KeyEntry{rootKey("root1"), rootKey("root4"), rootKey("root5")}
	s4ok := g.signedBy(g.stmt(4, 2, t4, with(newRoots, cmdB)...), "root1", "root2", "root4")
	a := ScenarioCase{Name: "genesis-rotation-removal", Doc: "pin yok; bootstrap genesis, zincir halkaları, ret vakaları ve kök değişimi"}
	a.Steps = []StepCase{
		g.step("genesis", "epoch 1, 3 kök eşik 2, r1+r2 imzalı: kendi eşiğiyle tutarlı → bootstrap", "ok", "bootstrap", false, 1, nowS, s1),
		g.step("rotation-add-cmdB", "epoch 2: cmdB eklenir, r1+r3 imzalı", "ok", "chain", false, 2, nowS, s2),
		g.step("replay-epoch-2", "epoch 2 yeniden sunulur", "stale_epoch", "", false, 2, nowS, s2),
		g.step("old-epoch-1", "epoch 1 yeniden sunulur", "stale_epoch", "", false, 2, nowS, s1),
		g.step("threshold-not-met", "epoch 3 yalnız r1 imzalı (eşik 2)", "threshold_not_met", "", false, 2, nowS,
			g.signedBy(g.stmt(3, 2, t3, with(roots3(), cmdB)...), "root1")),
		g.step("duplicate-signer-counts-once", "epoch 3 r1 iki kez imzalı", "threshold_not_met", "", false, 2, nowS,
			func() cmdenvelope.Statement {
				st := g.signedBy(g.stmt(3, 2, t3, with(roots3(), cmdB)...), "root1")
				st.Signatures = append(st.Signatures, st.Signatures[0])
				return st
			}()),
		g.step("command-key-signs-statement", "epoch 3 yalnız komut anahtarı imzalı", "signer_not_root", "", false, 2, nowS,
			g.signedBy(g.stmt(3, 2, t3, with(roots3(), cmdB)...), "cmdB")),
		g.step("forged-signature", "epoch 3: r1 geçerli, r2 imzasının tek biti bozuk", "threshold_not_met", "", false, 2, nowS,
			func() cmdenvelope.Statement {
				st := g.signedBy(g.stmt(3, 2, t3, with(roots3(), cmdB)...), "root1", "root2")
				st.Signatures[1].Sig = append([]byte(nil), st.Signatures[1].Sig...)
				st.Signatures[1].Sig[0] ^= 1
				return st
			}()),
		g.step("skipped-epoch-without-pin", "epoch 5, pin imzası yok", "epoch_skipped", "", false, 2, nowS,
			g.signedBy(g.stmt(5, 2, t4, with(roots3(), cmdB)...), "root1", "root2")),
		g.step("removal-of-cmdA", "epoch 3: cmdA kaldırılır, r2+r3 imzalı", "ok", "chain", false, 3, nowS, s3),
		g.step("root-change-missing-new-quorum", "epoch 4: kök kümesi {r1,r4,r5}; yalnız eski eşik (r1,r2) imzaladı", "threshold_not_met", "", false, 3, nowS,
			g.signedBy(g.stmt(4, 2, t4, with(newRoots, cmdB)...), "root1", "root2")),
		g.step("root-change-missing-old-quorum", "epoch 4: yeni küme eşiği (r1,r4) var, eski kümeden yalnız r1", "threshold_not_met", "", false, 3, nowS,
			g.signedBy(g.stmt(4, 2, t4, with(newRoots, cmdB)...), "root1", "root4")),
		g.step("root-change-both-quorums", "epoch 4: eski (r1,r2) ve yeni (r1,r4) eşik imzaladı", "ok", "chain", false, 4, nowS, s4ok),
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
			g.signedBy(g.stmt(1, 2, t1, with(roots3(), cmdA)...), "root2", "root3")),
		g.step("pin-signed-genesis", "tek pin imzası yeter (eşik aranmaz)", "ok", "pin", false, 1, nowS, p1),
		g.step("chain-hop-without-pin", "epoch 2: pin imzasız, mevcut eşik (r2,r3)", "ok", "chain", false, 2, nowS, p2),
		g.step("jump-without-pin", "epoch 12 pin imzasız (r2,r3)", "epoch_skipped", "", false, 2, nowS,
			g.signedBy(g.stmt(12, 2, t3, with(roots3(), cmdB)...), "root2", "root3")),
		g.step("pin-signed-jump-to-9", "epoch 2 → 9 pin imzasıyla; kök kümesi bile değişebilir", "ok", "pin", true, 9, nowS, p9),
		g.step("pin-cannot-go-back", "pin imzası da epoch geriletemez", "stale_epoch", "", false, 9, nowS,
			g.signedBy(g.stmt(5, 1, t3, jumpKeys...), "root1")),
		g.step("old-root-quorum-no-longer-works", "kök kümesi {root4}: eski r2,r3 imzalı epoch 10 reddedilir", "threshold_not_met", "", false, 9, nowS,
			g.signedBy(g.stmt(10, 1, t4, jumpKeys...), "root2", "root3")),
	}
	b.KeyChecks = []KeyCheckCase{{"cmdB-valid-after-jump", idOf("cmdB"), nowS, "ok"}, {"cmdA-gone-after-jump", idOf("cmdA"), nowS, "key_not_in_chain"}}
	out = append(out, b)

	// --- C: süresi dolmuş anahtarlar ---
	r2short := rootKey("root2")
	r2short.NotAfterNS = BaseNS + 30*int64(time.Minute)
	cmdShort := cmdKey("cmdA", BaseNS, BaseNS+10*hour)
	genExpiredSigner := g.signedBy(g.stmt(1, 2, t1, with([]cmdenvelope.KeyEntry{rootKey("root1"), r2short, rootKey("root3")}, cmdShort)...), "root1", "root2")
	early := BaseNS + 10*int64(time.Minute)
	genOK := g.signedBy(g.stmt(1, 2, early, with([]cmdenvelope.KeyEntry{rootKey("root1"), r2short, rootKey("root3")}, cmdShort)...), "root1", "root2")
	hop2Bad := g.signedBy(g.stmt(2, 2, t2, with([]cmdenvelope.KeyEntry{rootKey("root1"), r2short, rootKey("root3")}, cmdShort)...), "root1", "root2")
	hop2OK := g.signedBy(g.stmt(2, 2, t2, with([]cmdenvelope.KeyEntry{rootKey("root1"), r2short, rootKey("root3")}, cmdShort)...), "root1", "root3")
	c := ScenarioCase{Name: "expired-keys", Doc: "kök imzacı penceresi bildirimin issued_at anında değerlendirilir; komut anahtarı süresi zincirde denetlenir"}
	c.Steps = []StepCase{
		g.step("genesis-signed-by-expired-root", "genesis issued=base+1h, root2 base+30dk'da sona erdi → eşik sağlanmaz", "threshold_not_met", "", false, 0, nowS, genExpiredSigner),
		g.step("genesis-signed-inside-window", "genesis issued=base+10dk, root2 penceresi içinde", "ok", "bootstrap", false, 1, nowS, genOK),
		g.step("hop-signed-by-expired-root", "epoch 2 issued=base+2h: root2 artık geçersiz, tek geçerli imza r1", "threshold_not_met", "", false, 1, nowS, hop2Bad),
		g.step("hop-signed-by-valid-roots", "epoch 2: r1+r3", "ok", "chain", false, 2, nowS, hop2OK),
	}
	c.KeyChecks = []KeyCheckCase{
		{"cmdA-inside-window", idOf("cmdA"), BaseNS + 5*hour, "ok"},
		{"cmdA-expired", idOf("cmdA"), BaseNS + 11*hour, "key_expired"},
		{"cmdA-before-not-before", idOf("cmdA"), BaseNS - 1, "not_yet_valid"},
	}
	out = append(out, c)

	// --- D: tek kök, eşik 1, bootstrap ---
	d := ScenarioCase{Name: "single-root-small-deployment", Doc: "1-of-1 kök; bootstrap yalnız kendi eşiğiyle"}
	d.Steps = []StepCase{
		g.step("genesis-one-of-one", "tek kök kendi bildirimini imzalar", "ok", "bootstrap", false, 1, nowS,
			g.signedBy(g.stmt(1, 1, t1, rootKey("root1"), cmdA), "root1")),
	}
	out = append(out, d)
	return out
}
