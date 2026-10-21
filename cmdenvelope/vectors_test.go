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

var update = flag.Bool("update", false, "testdata/v2_vectors.json dosyasını yeniden üret (TEL DEĞİŞİKLİĞİ)")

const vectorsPath = "testdata/v2_vectors.json"

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
// olmalı. Tel biçimini (kanonik bayt, özet, imza) değiştiren her kod değişikliği burada
// kırılır; bilinçli değişiklik `-update` ile yeniden üretilir ve ajan sürümü gerektirir.
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
			"go test ./cmdenvelope -run TestGoldenVectors -update (ve ajan sürümü gerekir)")
	}
}

// TestGoldenVectors_Envelopes: her zarf vektörü dosyadaki bayt ve kararlarla doğrulanır;
// yalnız dosyadaki veri kullanılır (üreticiye bakılmaz).
func TestGoldenVectors_Envelopes(t *testing.T) {
	f := loadVectors(t)
	for _, c := range f.Envelopes {
		t.Run(c.Name, func(t *testing.T) {
			env, err := c.Envelope.Envelope()
			if err != nil {
				t.Fatal(err)
			}
			if c.CanonicalHex != "" {
				msg, err := cmdenvelope.CanonicalV2(vectorsDevice(), env)
				if err != nil {
					t.Fatalf("kanonik bayt kurulamadı: %v", err)
				}
				if hex.EncodeToString(msg) != c.CanonicalHex {
					t.Fatalf("kanonik bayt ayrıştı:\n got %x\nwant %s", msg, c.CanonicalHex)
				}
				sum := sha256.Sum256(msg)
				if hex.EncodeToString(sum[:]) != c.DigestHex {
					t.Fatal("envelope_digest ayrıştı")
				}
				pd, err := cmdenvelope.ParamsDigest(env.Params)
				if err != nil || hex.EncodeToString(pd[:]) != c.ParamsDigestHex {
					t.Fatalf("params özeti ayrıştı: %v", err)
				}
				fields, err := cmdenvelope.ParseCanonicalV2(msg)
				if err != nil {
					t.Fatalf("kanonik bayt ayrıştırılamadı: %v", err)
				}
				if again, _ := fields.Encode(); !bytes.Equal(again, msg) {
					t.Fatal("Parse→Encode bayt-bayt aynı değil")
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
			v, verr := cmdenvelope.VerifyV2(env, cmdenvelope.VerifyInput{DeviceID: c.DeviceID, Keys: keys, Now: now})
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

func vectorsDevice() string { return vectors.Device }

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
			// Dosyadaki yapısal params'tan da aynı bayt/özet çıkmalı.
			var in []cmdenvelope.Param
			for _, p := range c.Params {
				in = append(in, cmdenvelope.Param{Key: p.Key, Value: p.Value, List: p.List, IsList: p.IsList})
			}
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
				st, err := s.Statement.Statement()
				if err != nil {
					t.Fatal(err)
				}
				byName[s.Name] = st
				if s.CanonicalHex != "" {
					msg, err := cmdenvelope.CanonicalStatement(st)
					if err != nil || hex.EncodeToString(msg) != s.CanonicalHex {
						t.Fatalf("%s: kanonik bildirim baytı ayrıştı (%v)", s.Name, err)
					}
					parsed, err := cmdenvelope.ParseStatement(msg)
					if err != nil {
						t.Fatalf("%s: ayrıştırılamadı: %v", s.Name, err)
					}
					if again, _ := cmdenvelope.CanonicalStatement(parsed); !bytes.Equal(again, msg) {
						t.Fatalf("%s: Parse→Canonical bayt-bayt aynı değil", s.Name)
					}
				}
				acc, err := cmdenvelope.ApplyStatement(local, st, pins, nowOf(s.NowNS))
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

// TestGoldenVectors_Coverage: vektör kümesi eksiltilemez — her komut sınıfı, her S2 ret nedeni
// ve tasarım matrisinin S2 satırları için zorunlu vektörler dosyada bulunmalı.
func TestGoldenVectors_Coverage(t *testing.T) {
	f := loadVectors(t)
	have := map[string]bool{}
	reasons := map[string]bool{}
	okTypes := map[string]bool{}
	var withExtra, nonZeroSeq int
	for _, c := range f.Envelopes {
		have[c.Name] = true
		reasons[c.Expect] = true
		if c.Expect == "ok" {
			okTypes[c.Envelope.Type] = true
			if len(c.Envelope.ExtraSignatures) > 0 {
				withExtra++
			}
			if c.Envelope.Sequence != 0 {
				nonZeroSeq++
			}
		}
	}
	for _, s := range cmdenvelope.All() {
		if !okTypes[s.Name] {
			t.Errorf("komut sınıfı %s için geçerli vektör yok", s.Name)
		}
	}
	if withExtra < 2 || nonZeroSeq < 2 {
		t.Errorf("ek imzalı (%d) ve sıfırdan farklı sequence'li (%d) vektörler eksik", withExtra, nonZeroSeq)
	}
	for _, r := range []cmdenvelope.Reason{
		cmdenvelope.ReasonUnsupportedVersion, cmdenvelope.ReasonMalformedEnvelope, cmdenvelope.ReasonMalformedParams,
		cmdenvelope.ReasonUnknownType, cmdenvelope.ReasonBadLifetime, cmdenvelope.ReasonUnknownKey,
		cmdenvelope.ReasonKeyExpired, cmdenvelope.ReasonBadSignature, cmdenvelope.ReasonBadDeviceID,
		cmdenvelope.ReasonClockUnsynced, cmdenvelope.ReasonNotYetValid, cmdenvelope.ReasonExpired,
	} {
		if !reasons[string(r)] {
			t.Errorf("ret nedeni %s için vektör yok", r)
		}
	}
	for _, name := range []string{
		"device-id-mixed-case", "correlation-id-nul", "correlation-id-overlong", "command-id-uppercase",
		"nonce-uppercase-hex", "key-id-64-bit", "extra-signatures-both-trusted", "nonzero-sequence",
		"v1-signature-presented-as-v2", "trust-statement-signature-presented-as-envelope", "wrong-device",
	} {
		if !have[name] {
			t.Errorf("zorunlu vektör %q yok", name)
		}
	}
	scen := map[string]bool{}
	steps := map[string]bool{}
	for _, s := range f.Scenarios {
		scen[s.Name] = true
		for _, st := range s.Steps {
			steps[st.Name] = true
		}
	}
	for _, n := range []string{"genesis-rotation-removal", "pin-signed-jump", "expired-keys"} {
		if !scen[n] {
			t.Errorf("zorunlu senaryo %q yok", n)
		}
	}
	for _, n := range []string{"genesis", "rotation-add-cmdB", "pin-signed-jump-to-9", "threshold-not-met",
		"command-key-signs-statement", "hop-signed-by-expired-root", "root-change-both-quorums", "genesis-one-of-one"} {
		if !steps[n] {
			t.Errorf("zorunlu bildirim adımı %q yok", n)
		}
	}
}
