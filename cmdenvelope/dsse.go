package cmdenvelope

// DSSE (Dead Simple Signing Envelope) — komut zarfı v2 ve güven bildirimi bu zarfla taşınır.
// Biçim: https://github.com/secure-systems-lab/dsse (protocol.md, v1.0). Bu dosya yalnız
// standart kütüphaneyi kullanır; PAE ve JSON kodlaması burada elle yazılmıştır.
//
//	envelope  = { payloadType, payload (bayt), signatures: [ { keyid, sig } ] }
//	imza      = Ed25519( PAE(payloadType, payload) )
//	PAE       = "DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload
//	            (SP = 0x20; LEN = bayt uzunluğunun ASCII ondalık gösterimi, başında sıfır yok)
//
// `keyid` YALNIZCA doğrulanmamış bir ipucudur: doğrulayan, güvendiği anahtarı keyid ile bulur
// ve imzayı O anahtarla doğrular; keyid hiçbir şeyi kanıtlamaz. Gövde (payload) tüm imzacılar
// için AYNIDIR.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
)

// Yük türleri. Sürüm yük türünde taşınır; farklı bir tür asla başka bir nesne olarak kabul
// edilmez ve PAE içinde imzaya dahildir (alanlar-arası imza yeniden kullanımı olmaz).
const (
	PayloadTypeCommand = "application/vnd.kut.cmd.v2"
	PayloadTypeTrust   = "application/vnd.kut.trust.v2"

	payloadTypeCommandPrefix = "application/vnd.kut.cmd."
	payloadTypeTrustPrefix   = "application/vnd.kut.trust."
)

// DSSE sınırları.
const (
	// MaxDSSESignatures, bir zarftaki azami imza girdisi sayısıdır (komut ve bildirim).
	MaxDSSESignatures = 8
	// MaxDSSEPayloadBytes, tel üzerindeki azami gövde boyutudur (komut gövdesi ~0.7 KiB,
	// 32 anahtarlı bildirim ~3.1 KiB).
	MaxDSSEPayloadBytes = 4096
	// MaxDSSEJSONBytes, JSON gösterimi için azami girdi boyutudur (base64 şişmesi dahil).
	MaxDSSEJSONBytes = 16 << 10
)

// DSSESignature, zarftaki bir imza girdisidir. KeyID doğrulanmamış ipucudur.
type DSSESignature struct {
	KeyID string
	Sig   []byte
}

// DSSE, bir DSSE zarfıdır.
type DSSE struct {
	PayloadType string
	Payload     []byte
	Signatures  []DSSESignature
}

// PAE, DSSE "Pre-Authentication Encoding"idir. Uzunluklar bayt cinsindendir ve ASCII
// ondalık yazılır.
func PAE(payloadType string, payload []byte) []byte {
	b := make([]byte, 0, 32+len(payloadType)+len(payload))
	b = append(b, "DSSEv1 "...)
	b = strconv.AppendInt(b, int64(len(payloadType)), 10)
	b = append(b, ' ')
	b = append(b, payloadType...)
	b = append(b, ' ')
	b = strconv.AppendInt(b, int64(len(payload)), 10)
	b = append(b, ' ')
	return append(b, payload...)
}

// SignDSSE, PAE(payloadType, payload) üzerinde Ed25519 imzası üretir; keyid olarak
// KeyID(pub) yazılır.
func SignDSSE(priv ed25519.PrivateKey, payloadType string, payload []byte) (DSSESignature, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return DSSESignature{}, newErr(ReasonUnknownKey, "geçersiz özel anahtar boyutu")
	}
	return DSSESignature{
		KeyID: KeyID(priv.Public().(ed25519.PublicKey)),
		Sig:   ed25519.Sign(priv, PAE(payloadType, payload)),
	}, nil
}

// CoSign, mevcut zarfın gövdesini priv ile (ek imza olarak) imzalar; aynı keyid'nin önceki
// girdisi değiştirilir. Gövde değişmez.
func CoSign(priv ed25519.PrivateKey, d DSSE) (DSSE, error) {
	s, err := SignDSSE(priv, d.PayloadType, d.Payload)
	if err != nil {
		return DSSE{}, err
	}
	out := DSSE{PayloadType: d.PayloadType, Payload: d.Payload, Signatures: append([]DSSESignature(nil), d.Signatures...)}
	for i := range out.Signatures {
		if out.Signatures[i].KeyID == s.KeyID {
			out.Signatures[i] = s
			return out, nil
		}
	}
	if len(out.Signatures) >= MaxDSSESignatures {
		return DSSE{}, newErr(ReasonMalformedEnvelope, "azami %d imza aşıldı", MaxDSSESignatures)
	}
	out.Signatures = append(out.Signatures, s)
	return out, nil
}

// validateShape, zarfın BİÇİMSEL değişmezlerini denetler (imza doğrulamaz): gövde boyutu,
// imza sayısı (1..8), her keyid 32 küçük harfli hex, her imza 64 bayt. Yinelenen keyid
// biçim hatası DEĞİLDİR; doğrulamada bir kez sayılır. reason, çağıranın hata nedenidir.
func (d DSSE) validateShape(reason Reason) error {
	if n := len(d.Payload); n == 0 || n > MaxDSSEPayloadBytes {
		return newErr(reason, "gövde boyutu %d (1..%d olmalı)", n, MaxDSSEPayloadBytes)
	}
	if n := len(d.Signatures); n == 0 || n > MaxDSSESignatures {
		return newErr(reason, "imza sayısı %d (1..%d olmalı)", n, MaxDSSESignatures)
	}
	for _, s := range d.Signatures {
		if !isLowerHex(s.KeyID, KeyIDHexLen) || len(s.Sig) != SignatureLen {
			return newErr(reason, "imza girdisi biçimi geçersiz")
		}
	}
	return nil
}

// ---- JSON gösterimi (DSSE standardı: payloadType, payload, signatures[keyid, sig]) ----

type dsseJSON struct {
	PayloadType string        `json:"payloadType"`
	Payload     string        `json:"payload"`
	Signatures  []dsseSigJSON `json:"signatures"`
}

type dsseSigJSON struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// MarshalJSON, zarfı standart DSSE JSON'u olarak kodlar (payload ve sig: dolgulu standart
// base64).
func (d DSSE) MarshalJSON() ([]byte, error) {
	j := dsseJSON{PayloadType: d.PayloadType, Payload: base64.StdEncoding.EncodeToString(d.Payload), Signatures: []dsseSigJSON{}}
	for _, s := range d.Signatures {
		j.Signatures = append(j.Signatures, dsseSigJSON{KeyID: s.KeyID, Sig: base64.StdEncoding.EncodeToString(s.Sig)})
	}
	return json.Marshal(j)
}

// ParseDSSEJSON, DSSE JSON'unu KATI ayrıştırır: bilinmeyen alan, artık veri, dolgusuz/URL-safe
// base64, aşırı boyut ve imza sayısı sınırı aşımı reddedilir. Yalnız biçimi doğrular; yük
// türünü ve imzaları denetlemez.
func ParseDSSEJSON(b []byte) (DSSE, error) {
	if len(b) == 0 || len(b) > MaxDSSEJSONBytes {
		return DSSE{}, newErr(ReasonMalformedEnvelope, "JSON boyutu %d (1..%d olmalı)", len(b), MaxDSSEJSONBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var j dsseJSON
	if err := dec.Decode(&j); err != nil {
		return DSSE{}, newErr(ReasonMalformedEnvelope, "JSON: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return DSSE{}, newErr(ReasonMalformedEnvelope, "JSON sonrasında artık veri")
	}
	if len(j.Signatures) > MaxDSSESignatures {
		return DSSE{}, newErr(ReasonMalformedEnvelope, "%d imza > %d", len(j.Signatures), MaxDSSESignatures)
	}
	if base64.StdEncoding.DecodedLen(len(j.Payload)) > MaxDSSEPayloadBytes {
		return DSSE{}, newErr(ReasonMalformedEnvelope, "gövde > %d bayt", MaxDSSEPayloadBytes)
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(j.Payload)
	if err != nil {
		return DSSE{}, newErr(ReasonMalformedEnvelope, "payload base64: %v", err)
	}
	d := DSSE{PayloadType: j.PayloadType, Payload: payload}
	for _, s := range j.Signatures {
		sig, err := base64.StdEncoding.Strict().DecodeString(s.Sig)
		if err != nil {
			return DSSE{}, newErr(ReasonMalformedEnvelope, "sig base64: %v", err)
		}
		d.Signatures = append(d.Signatures, DSSESignature{KeyID: s.KeyID, Sig: sig})
	}
	return d, nil
}

func (d DSSE) String() string {
	return fmt.Sprintf("dsse{%s, %d bayt, %d imza}", d.PayloadType, len(d.Payload), len(d.Signatures))
}
