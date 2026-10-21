package cmdenvelope

import (
	"bytes"
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
