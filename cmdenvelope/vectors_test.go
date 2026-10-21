package cmdenvelope_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kut.corp/suite/cmdenvelope"
	"kut.corp/suite/cmdenvelope/internal/vectors"
)

var update = flag.Bool("update", false, "contracts/testvectors/cmdenvelope/v2_vectors.json dosyasını yeniden üret (TEL DEĞİŞİKLİĞİ)")

// vectorsPath: sunucu ve ajan testlerinin ortak okuduğu sözleşme vektörleri.
const vectorsPath = "../contracts/testvectors/cmdenvelope/v2_vectors.json"

func loadVectors(t *testing.T) vectors.File {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var f vectors.File
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestGoldenVectors_BytePinned: dosya, sabit tohumlardan üretilen çıktıyla BAYT-BAYT aynı
// olmalı. Tel biçimini (gövde, PAE, özet, imza) değiştiren her kod değişikliği burada kırılır;
// bilinçli değişiklik `-update` ile yeniden üretilir ve ajan sürümü gerektirir.
func TestGoldenVectors_BytePinned(t *testing.T) {
	got, err := vectors.Generate()
	if err != nil {
		t.Fatal(err)
	}
	again, _ := vectors.Generate()
	if !bytes.Equal(got, again) {
		t.Fatal("üretici deterministik değil")
	}
	if *update {
		if err := os.MkdirAll(filepath.Dir(vectorsPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorsPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s yeniden üretildi (%d bayt)", vectorsPath, len(got))
		return
	}
	want, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	// Git CRLF normalizasyonu dosya içeriğini değiştirebilir: yalnız satır sonu farkı yok sayılır.
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Fatal("v2_vectors.json üretilen çıktıyla ayrıştı — tel biçimi DEĞİŞTİ. Bilinçliyse: " +
			"go test ./cmdenvelope -run TestGoldenVectors_BytePinned -update (ve ajan sürümü gerekir)")
	}
}

func TestGoldenVectors_PAE(t *testing.T) {
	f := loadVectors(t)
	for _, c := range f.PAE {
		payload, err := hex.DecodeString(c.PayloadHex)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(cmdenvelope.PAE(c.PayloadType, payload)); got != c.PAEHex {
			t.Errorf("%s: PAE %s, dosyada %s", c.Name, got, c.PAEHex)
		}
	}
	// Spesifikasyon örneği bağımsız olarak sabit: bu satır dosyadan okunmaz.
	if got := string(cmdenvelope.PAE("http://example.com/HelloWorld", []byte("hello world"))); got != "DSSEv1 29 http://example.com/HelloWorld 11 hello world" {
		t.Fatalf("PAE spesifikasyon örneği: %q", got)
	}
}

// TestGoldenVectors_Envelopes: her zarf vektörü dosyadaki bayt ve kararlarla doğrulanır;
// yalnız dosyadaki veri kullanılır (üreticiye bakılmaz).
func TestGoldenVectors_Envelopes(t *testing.T) {
	f := loadVectors(t)
	for _, c := range f.Envelopes {
		t.Run(c.Name, func(t *testing.T) {
			d, err := c.DSSE.ToDSSE()
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(d.Payload) != c.PayloadHex {
				t.Fatal("payload_hex, dsse.payload ile uyuşmuyor")
			}
			pae := cmdenvelope.PAE(d.PayloadType, d.Payload)
			if hex.EncodeToString(pae) != c.PAEHex {
				t.Fatalf("PAE ayrıştı:\n got %x\nwant %s", pae, c.PAEHex)
			}
			sum := sha256.Sum256(pae)
			if hex.EncodeToString(sum[:]) != c.DigestHex {
				t.Fatal("envelope_digest (sha256 PAE) ayrıştı")
			}
			// Çözülmüş gövde görünümü, gövdenin ayrıştırılmış haliyle aynı olmalı.
			fields, perr := cmdenvelope.ParseCanonicalV2(d.Payload)
			if (c.Body != nil) != (perr == nil) {
				t.Fatalf("body görünümü ile ayrıştırma sonucu tutarsız (body=%v, err=%v)", c.Body != nil, perr)
			}
			if perr == nil {
				if again, _ := fields.Encode(); !bytes.Equal(again, d.Payload) {
					t.Fatal("Parse→Encode bayt-bayt aynı değil")
				}
				b := c.Body
				if b.CommandID != fields.CommandID || b.DeviceID != fields.DeviceID || b.TenantID != fields.TenantID || b.Type != fields.Type ||
					b.RequestedBy != fields.RequestedBy || b.ApprovedBy != fields.ApprovedBy || b.CorrelationID != fields.CorrelationID ||
					b.Sequence != fields.Sequence || b.Nonce != fields.Nonce || b.IssuedAtNS != fields.IssuedAtNS || b.ExpiresAtNS != fields.ExpiresAtNS ||
					b.ParamsDigestHex != hex.EncodeToString(fields.ParamsDigest[:]) {
					t.Fatalf("body görünümü gövdeyle uyuşmuyor: %+v vs %+v", b, fields)
				}
				// Gövdeyi yeniden kurmak (Envelope→CanonicalV2) aynı baytı vermeli.
				rebuilt, err := cmdenvelope.CanonicalV2(fields.DeviceID, cmdenvelope.Envelope{
					CommandID: fields.CommandID, TenantID: fields.TenantID, Type: fields.Type, RequestedBy: fields.RequestedBy,
					ApprovedBy: fields.ApprovedBy, CorrelationID: fields.CorrelationID, Sequence: fields.Sequence, Nonce: fields.Nonce,
					IssuedAtNS: fields.IssuedAtNS, ExpiresAtNS: fields.ExpiresAtNS, Params: vectors.ToParams(c.Params),
				})
				// Telde taşınan params gövdedeki özetle uyuşmayabilir (kurcalama vektörleri): yalnız uyuşuyorsa karşılaştır.
				if pd, e2 := cmdenvelope.ParamsDigest(vectors.ToParams(c.Params)); e2 == nil && pd == fields.ParamsDigest {
					if err != nil || !bytes.Equal(rebuilt, d.Payload) {
						t.Fatalf("gövde yeniden kurulamadı: %v", err)
					}
				}
			}
			keys, err := vectors.Entries(c.Keys)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Time{}
			if c.NowNS != 0 {
				now = time.Unix(0, c.NowNS)
			}
			v, verr := cmdenvelope.VerifyV2(d, vectors.ToParams(c.Params), cmdenvelope.VerifyInput{
				DeviceID: c.DeviceID, Keys: keys, Now: now, MinSignatures: c.MinSignatures,
				WireCommandID: c.WireCommandID, WireType: c.WireType,
			})
			if c.Expect == "ok" {
				if verr != nil {
					t.Fatalf("kabul bekleniyordu: %v", verr)
				}
				if hex.EncodeToString(v.Digest[:]) != c.DigestHex {
					t.Fatal("doğrulama özeti dosyadakiyle ayrıştı")
				}
				return
			}
			if verr == nil {
				t.Fatalf("ret bekleniyordu (%s), kabul edildi", c.Expect)
			}
			if got := string(cmdenvelope.ReasonOf(verr)); got != c.Expect {
				t.Fatalf("neden %q, beklenen %q (%v)", got, c.Expect, verr)
			}
		})
	}
}

func TestGoldenVectors_Params(t *testing.T) {
	f := loadVectors(t)
	for _, c := range f.Params {
		t.Run(c.Name, func(t *testing.T) {
			enc, err := hex.DecodeString(c.EncodedHex)
			if err != nil {
				t.Fatal(err)
			}
			ps, err := cmdenvelope.ParseParams(enc)
			if c.Expect != "ok" {
				if err == nil {
					t.Fatalf("ret bekleniyordu (%s)", c.Expect)
				}
				if got := string(cmdenvelope.ReasonOf(err)); got != c.Expect {
					t.Fatalf("neden %q, beklenen %q", got, c.Expect)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if again, _ := cmdenvelope.EncodeParams(ps); !bytes.Equal(again, enc) {
				t.Fatal("Parse→Encode bayt-bayt aynı değil")
			}
			in := vectors.ToParams(c.Params)
			d, err := cmdenvelope.ParamsDigest(in)
			if err != nil || hex.EncodeToString(d[:]) != c.DigestHex {
				t.Fatalf("özet ayrıştı: %v", err)
			}
			if viaIn, _ := cmdenvelope.EncodeParams(in); !bytes.Equal(viaIn, enc) {
				t.Fatal("yapısal params kodlaması dosyadakiyle ayrıştı")
			}
		})
	}
}

func TestGoldenVectors_ParamMaps(t *testing.T) {
	f := loadVectors(t)
	for _, c := range f.ParamMaps {
		t.Run(c.Name, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal([]byte(c.JSON), &m); err != nil {
				t.Fatal(err)
			}
			_, err := cmdenvelope.ParamsFromMap(m)
			if c.Expect == "ok" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if got := string(cmdenvelope.ReasonOf(err)); got != c.Expect {
				t.Fatalf("neden %q, beklenen %q (%v)", got, c.Expect, err)
			}
		})
	}
}

func TestGoldenVectors_TrustScenarios(t *testing.T) {
	f := loadVectors(t)
	for _, sc := range f.Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			pins, err := vectors.Pubs(sc.PinsHex)
			if err != nil {
				t.Fatal(err)
			}
			var local *cmdenvelope.Statement
			byName := map[string]cmdenvelope.Statement{}
			for _, s := range sc.Steps {
				d, err := s.DSSE.ToDSSE()
				if err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(d.Payload) != s.PayloadHex {
					t.Fatalf("%s: payload_hex, dsse.payload ile uyuşmuyor", s.Name)
				}
				// Gövde ayrıştırılabiliyorsa görünüm ve gidiş-dönüş tutarlı olmalı.
				body, perr := cmdenvelope.ParseStatement(d.Payload)
				if (s.Body != nil) != (perr == nil) {
					t.Fatalf("%s: body görünümü ile ayrıştırma tutarsız (%v)", s.Name, perr)
				}
				if perr == nil {
					if again, _ := cmdenvelope.CanonicalStatement(body); !bytes.Equal(again, d.Payload) {
						t.Fatalf("%s: Parse→Canonical bayt-bayt aynı değil", s.Name)
					}
					want, err := s.Body.Statement()
					if err != nil {
						t.Fatal(err)
					}
					if wb, _ := cmdenvelope.CanonicalStatement(want); !bytes.Equal(wb, d.Payload) {
						t.Fatalf("%s: body görünümü gövdeyle uyuşmuyor", s.Name)
					}
				}
				if st, err := cmdenvelope.ParseStatementDSSE(d); err == nil {
					byName[s.Name] = st
				}
				acc, err := cmdenvelope.ApplyStatementDSSE(local, d, pins, nowOf(s.NowNS))
				if s.Expect == "ok" {
					if err != nil {
						t.Fatalf("%s: kabul bekleniyordu: %v", s.Name, err)
					}
					if string(acc.Mode) != s.Mode || acc.EpochJump != s.EpochJump {
						t.Fatalf("%s: mod %s/%v, beklenen %s/%v", s.Name, acc.Mode, acc.EpochJump, s.Mode, s.EpochJump)
					}
					c := acc.Statement
					local = &c
				} else {
					if err == nil {
						t.Fatalf("%s: ret bekleniyordu (%s)", s.Name, s.Expect)
					}
					if got := string(cmdenvelope.ReasonOf(err)); got != s.Expect {
						t.Fatalf("%s: neden %q, beklenen %q (%v)", s.Name, got, s.Expect, err)
					}
				}
				var epoch uint64
				if local != nil {
					epoch = local.Epoch
				}
				if epoch != s.EpochAfter {
					t.Fatalf("%s: adım sonrası epoch %d, beklenen %d (başarısız adım durumu değiştirmemeli)", s.Name, epoch, s.EpochAfter)
				}
			}
			for _, k := range sc.KeyChecks {
				if local == nil {
					t.Fatal("anahtar denetimi için yerel durum yok")
				}
				_, err := cmdenvelope.ChainKeyValid(*local, k.KeyID, nowOf(k.NowNS))
				got := "ok"
				if err != nil {
					got = string(cmdenvelope.ReasonOf(err))
				}
				if got != k.Expect {
					t.Errorf("anahtar denetimi %s: %s, beklenen %s", k.Name, got, k.Expect)
				}
			}
			for _, cc := range sc.ChainChecks {
				var chain []cmdenvelope.Statement
				for _, n := range cc.Steps {
					st, ok := byName[n]
					if !ok {
						t.Fatalf("zincir denetimi %s: bilinmeyen adım %s", cc.Name, n)
					}
					chain = append(chain, st)
				}
				_, err := cmdenvelope.VerifyChain(chain, pins, nowOf(cc.NowNS))
				got := "ok"
				if err != nil {
					got = string(cmdenvelope.ReasonOf(err))
				}
				if got != cc.Expect {
					t.Errorf("zincir denetimi %s: %s, beklenen %s", cc.Name, got, cc.Expect)
				}
			}
		})
	}
}

func nowOf(ns int64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// TestGoldenVectors_Coverage: vektör kümesi eksiltilemez — her komut sınıfı, her ret nedeni ve
// DSSE'ye özgü vakalar dosyada bulunmalı.
func TestGoldenVectors_Coverage(t *testing.T) {
	f := loadVectors(t)
	have := map[string]bool{}
	reasons := map[string]bool{}
	okTypes := map[string]bool{}
	var multiSig, nonZeroSeq int
	for _, c := range f.Envelopes {
		have[c.Name] = true
		reasons[c.Expect] = true
		if c.Expect == "ok" && c.Body != nil {
			okTypes[c.Body.Type] = true
			if len(c.DSSE.Signatures) > 1 {
				multiSig++
			}
			if c.Body.Sequence != 0 {
				nonZeroSeq++
			}
		}
	}
	for _, s := range cmdenvelope.All() {
		if !okTypes[s.Name] {
			t.Errorf("komut sınıfı %s için geçerli vektör yok", s.Name)
		}
	}
	if multiSig < 2 || nonZeroSeq < 2 {
		t.Errorf("çok imzalı (%d) ve sıfırdan farklı sequence'li (%d) vektörler eksik", multiSig, nonZeroSeq)
	}
	for _, r := range []cmdenvelope.Reason{
		cmdenvelope.ReasonUnsupportedVersion, cmdenvelope.ReasonMalformedEnvelope, cmdenvelope.ReasonMalformedParams,
		cmdenvelope.ReasonUnknownType, cmdenvelope.ReasonBadLifetime, cmdenvelope.ReasonUnknownKey,
		cmdenvelope.ReasonKeyExpired, cmdenvelope.ReasonBadSignature, cmdenvelope.ReasonBadDeviceID,
		cmdenvelope.ReasonClockUnsynced, cmdenvelope.ReasonNotYetValid, cmdenvelope.ReasonExpired,
		cmdenvelope.ReasonBadPayloadType, cmdenvelope.ReasonWrongDevice, cmdenvelope.ReasonInsufficientSignatures,
	} {
		if !reasons[string(r)] {
			t.Errorf("ret nedeni %s için vektör yok", r)
		}
	}
	for _, name := range []string{
		"verifier-device-id-mixed-case", "body-device-id-mixed-case", "correlation-id-nul", "correlation-id-overlong", "command-id-uppercase",
		"nonce-uppercase-hex", "keyid-64-bit", "two-signatures-both-trusted", "nonzero-sequence", "wrong-device",
		// DSSE'ye özgü
		"payload-type-v1", "payload-type-trust-on-command", "signature-over-body-without-pae", "signature-under-other-payload-type",
		"keyid-hint-points-at-wrong-key", "duplicate-keyid-counted-once", "duplicate-keyid-not-two-signatures", "unknown-extra-signer-ignored",
		"v1-signature-presented-as-v2", "trust-statement-signature-presented-as-envelope", "dual-control-wipe-approver-signature",
		"dual-control-wipe-approver-signature-missing", "eight-signatures-ok", "nine-signatures",
	} {
		if !have[name] {
			t.Errorf("zorunlu vektör %q yok", name)
		}
	}
	if len(f.PAE) < 3 {
		t.Error("PAE sabit örnekleri eksik")
	}
	scen := map[string]bool{}
	steps := map[string]bool{}
	for _, s := range f.Scenarios {
		scen[s.Name] = true
		for _, st := range s.Steps {
			steps[st.Name] = true
		}
	}
	for _, n := range []string{"genesis-rotation-removal", "pin-signed-jump", "expired-keys", "dsse-signature-handling"} {
		if !scen[n] {
			t.Errorf("zorunlu senaryo %q yok", n)
		}
	}
	for _, n := range []string{"genesis", "rotation-add-cmdB", "pin-signed-jump-to-9", "threshold-not-met",
		"command-key-signs-statement", "hop-signed-by-expired-root", "root-change-both-quorums", "genesis-one-of-one",
		"wrong-payload-type", "signatures-over-body-without-pae", "keyid-hint-points-at-other-root", "unknown-extra-signer-ignored"} {
		if !steps[n] {
			t.Errorf("zorunlu bildirim adımı %q yok", n)
		}
	}
}
