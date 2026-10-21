package cmdenvelope

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

// Güven sınırını aşan ham bayt ayrıştırıcıları: rastgele girdide panik olmamalı ve kabul
// edilen her girdi için Encode(Parse(b)) == b (kanonik biçim tektir) olmalıdır.

func FuzzParseCanonicalV2(f *testing.F) {
	e := tEnv()
	e.ApprovedBy = "admin:approver"
	e.Params = []Param{StringParam("a", "b"), ListParam("c", "d")}
	if msg, err := CanonicalV2(tDevice, e); err == nil {
		f.Add(msg)
		f.Add(msg[:len(msg)/2])
		f.Add(append(append([]byte(nil), msg...), 0))
	}
	f.Add([]byte{})
	f.Add(appendLP(nil, DomainEnvelopeV2))
	f.Fuzz(func(t *testing.T, b []byte) {
		fl, err := ParseCanonicalV2(b)
		if err != nil {
			return
		}
		again, err := fl.Encode()
		if err != nil {
			t.Fatalf("ayrıştırılan alanlar kodlanamadı: %v", err)
		}
		if !bytes.Equal(again, b) {
			t.Fatalf("kanonik olmayan girdi kabul edildi:\n in  %x\n out %x", b, again)
		}
	})
}

func FuzzParseParams(f *testing.F) {
	enc, _ := EncodeParams([]Param{StringParam("a", "b"), ListParam("c", "d", "")})
	f.Add(enc)
	f.Add(enc[:len(enc)-1])
	f.Add(appendLP(nil, DomainParamsV2))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		ps, err := ParseParams(b)
		if err != nil {
			return
		}
		again, err := EncodeParams(ps)
		if err != nil {
			t.Fatalf("ayrıştırılan params kodlanamadı: %v", err)
		}
		if !bytes.Equal(again, b) {
			t.Fatalf("kanonik olmayan params kabul edildi:\n in  %x\n out %x", b, again)
		}
		if _, err := ParamsDigest(ps); err != nil {
			t.Fatal(err)
		}
	})
}

func FuzzParseStatement(f *testing.F) {
	g := Statement{Epoch: 1, RootThreshold: 1, IssuedAtNS: tBase,
		Keys: []KeyEntry{tRoot("root1"), tCmd("cmdA", tBase, tCmdEnd)}}
	if msg, err := CanonicalStatement(g); err == nil {
		f.Add(msg)
		f.Add(msg[:len(msg)-3])
		f.Add(append(append([]byte(nil), msg...), 1, 2))
	}
	f.Add([]byte{})
	f.Add(appendLP(nil, DomainTrustV2))
	f.Fuzz(func(t *testing.T, b []byte) {
		st, err := ParseStatement(b)
		if err != nil {
			return
		}
		again, err := CanonicalStatement(st)
		if err != nil {
			t.Fatalf("ayrıştırılan bildirim kodlanamadı: %v", err)
		}
		if !bytes.Equal(again, b) {
			t.Fatalf("kanonik olmayan bildirim kabul edildi:\n in  %x\n out %x", b, again)
		}
	})
}

// FuzzVerifyV2: rastgele alan değerleriyle VerifyV2 panik atmaz; kabul edilen zarf, güvenilen
// anahtarın GERÇEKTEN o ileti üzerinde attığı imzayı taşır (sahte kabul yok).
func FuzzVerifyV2(f *testing.F) {
	f.Add("a1b2c3d4-e5f6-4a07-98a9-b0c1d2e3f4a5", "acme", "QUARANTINE", "admin:x", "", "corr", uint64(1), "00112233445566778899aabbccddeeff", "k", "v", true)
	f.Add("", "", "", "", "", "", uint64(0), "", "", "", false)
	f.Add("\x00", "t\xff", "WIPE", "a\x1fb", "a\x1fb", "\x00", ^uint64(0), "zz", "K", "\xc0", true)
	signer := tKey("cmdA")
	keys := tCmdKeys("cmdA")
	f.Fuzz(func(t *testing.T, cmdID, tenant, typ, req, appr, corr string, seq uint64, nonce, pk, pv string, withSig bool) {
		e := Envelope{
			Version: 2, KeyID: KeyID(tPub("cmdA")), CommandID: cmdID, TenantID: tenant, Type: typ,
			RequestedBy: req, ApprovedBy: appr, CorrelationID: corr, Sequence: seq, Nonce: nonce,
			IssuedAtNS: tBase, ExpiresAtNS: tBase + int64(time.Hour), Params: []Param{StringParam(pk, pv)},
		}
		if withSig {
			if s, err := SignV2(signer, tDevice, e); err == nil {
				e = s
			} else {
				e.Signature = make([]byte, SignatureLen)
			}
		}
		v, err := VerifyV2(e, VerifyInput{DeviceID: tDevice, Keys: keys, Now: tNow()})
		if err != nil {
			return
		}
		// Kabul edildi: alanlar geçerli ve imza gerçekten bu iletiye ait olmalı.
		msg, cerr := CanonicalV2(tDevice, e)
		if cerr != nil {
			t.Fatalf("kabul edilen zarfın kanonik baytı kurulamıyor: %v", cerr)
		}
		if len(v.KeyIDs) == 0 || !VerifySignature(tPub("cmdA"), msg, e.Signature) {
			t.Fatal("imzasız/yanlış imzalı zarf kabul edildi")
		}
	})
}

// FuzzApplyStatement: rastgele epoch/eşik/imzacı kümeleriyle ApplyStatement panik atmaz ve
// kabul edilen zincir halkası bağımsız yeniden sayımla da eşiği sağlar.
func FuzzApplyStatement(f *testing.F) {
	f.Add(uint64(2), uint32(2), uint8(0b0011), false)
	f.Add(uint64(9), uint32(1), uint8(0b0001), true)
	f.Add(uint64(1), uint32(0), uint8(0), false)
	f.Add(uint64(3), uint32(3), uint8(0b10111), true)
	names := []string{"root1", "root2", "root3", "cmdA", "evil"}
	g := Statement{Epoch: 1, RootThreshold: 2, IssuedAtNS: tBase,
		Keys: []KeyEntry{tRoot("root1"), tRoot("root2"), tRoot("root3"), tCmd("cmdA", tBase, tCmdEnd)}}
	for _, s := range []string{"root1", "root2"} {
		g, _ = SignStatement(tKey(s), g)
	}
	f.Fuzz(func(t *testing.T, epoch uint64, threshold uint32, mask uint8, pinFirst bool) {
		st := Statement{Epoch: epoch, RootThreshold: threshold, IssuedAtNS: tBase + int64(time.Hour),
			Keys: []KeyEntry{tRoot("root1"), tRoot("root2"), tRoot("root3"), tCmd("cmdA", tBase, tCmdEnd)}}
		if st.Validate() != nil {
			return
		}
		var signers []string
		for i, n := range names {
			if mask&(1<<i) != 0 {
				st, _ = SignStatement(tKey(n), st)
				signers = append(signers, n)
			}
		}
		var pins []ed25519.PublicKey
		if pinFirst {
			pins = tPins("root1")
		}
		acc, err := ApplyStatement(&g, st, pins, tAt())
		if err != nil {
			return
		}
		if acc.Statement.Epoch <= g.Epoch {
			t.Fatalf("epoch geriledi/aynı kaldı: %d <= %d", acc.Statement.Epoch, g.Epoch)
		}
		rootSigners := 0
		pinSigned := false
		for _, s := range signers {
			if s == "root1" || s == "root2" || s == "root3" {
				rootSigners++
			}
			if pinFirst && s == "root1" {
				pinSigned = true
			}
		}
		switch acc.Mode {
		case AcceptPin:
			if !pinSigned {
				t.Fatal("pin imzası olmadan AcceptPin")
			}
		case AcceptChain:
			if epoch != g.Epoch+1 || rootSigners < int(g.RootThreshold) {
				t.Fatalf("zincir halkası kuralları ihlal edildi: epoch=%d kök imzası=%d", epoch, rootSigners)
			}
		default:
			t.Fatalf("yerel durum varken beklenmeyen mod %q", acc.Mode)
		}
	})
}
