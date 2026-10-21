// Package vectors, komut zarfı v2 (DSSE) ve güven bildirimi için ALTIN VEKTÖR dosyasının
// (contracts/testvectors/cmdenvelope/v2_vectors.json) şemasını ve deterministik üreticisini içerir.
//
// Vektörler SABİT tohumlardan üretilir (Ed25519 imzaları deterministiktir); dosya her
// çalıştırmada bayt-bayt aynı çıkar. Aynı JSON dosyasını ajan testleri de (W2-S6) okur:
// sunucu ve ajan aynı baytları üretip aynı kararı vermelidir. Dosyayı yeniden üretmek
// bir TEL DEĞİŞİKLİĞİDİR ve bilinçli yapılmalıdır:
//
//	go test ./cmdenvelope -run TestGoldenVectors_BytePinned -update
package vectors

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"kut.corp/suite/cmdenvelope"
)

// FormatVersion, vektör dosyası şemasının sürümüdür.
const FormatVersion = 2

// File, vektör dosyasının kökü.
type File struct {
	Format      int            `json:"format"`
	Description string         `json:"description"`
	Seeds       []SeedJSON     `json:"seeds"`
	PAE         []PAECase      `json:"pae"`
	Envelopes   []EnvelopeCase `json:"envelopes"`
	Params      []ParamsCase   `json:"params"`
	ParamMaps   []ParamMapCase `json:"param_maps"`
	Scenarios   []ScenarioCase `json:"scenarios"`
}

// SeedJSON, adlandırılmış bir test anahtarının tohumudur (YALNIZ test; üretimde kullanılmaz).
type SeedJSON struct {
	Name    string `json:"name"`
	SeedHex string `json:"seed_hex"`
	PubHex  string `json:"pub_hex"`
	KeyID   string `json:"keyid"`
}

// PAECase, DSSE PAE kodlamasının sabit örneğidir.
type PAECase struct {
	Name        string `json:"name"`
	PayloadType string `json:"payload_type"`
	PayloadHex  string `json:"payload_hex"`
	PAEHex      string `json:"pae_hex"`
}

// KeyJSON, güvenilen kümedeki ya da bildirimdeki bir anahtardır.
type KeyJSON struct {
	KeyID       string `json:"keyid"`
	PubHex      string `json:"pub_hex"`
	Role        string `json:"role"` // "ROOT" | "COMMAND"
	NotBeforeNS int64  `json:"not_before_ns"`
	NotAfterNS  int64  `json:"not_after_ns"`
}

// ParamJSON, tek parametre.
type ParamJSON struct {
	Key    string   `json:"key"`
	Value  string   `json:"value,omitempty"`
	List   []string `json:"list,omitempty"`
	IsList bool     `json:"is_list,omitempty"`
}

// DSSESigJSON ve DSSEJSON, standart DSSE JSON alan adlarını kullanır (payloadType, payload
// = dolgulu standart base64, signatures[keyid, sig = base64]).
type DSSESigJSON struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// DSSEJSON, DSSE zarfı.
type DSSEJSON struct {
	PayloadType string        `json:"payloadType"`
	Payload     string        `json:"payload"`
	Signatures  []DSSESigJSON `json:"signatures"`
}

// BodyJSON, komut gövdesinin ÇÖZÜLMÜŞ (bilgilendirici, test tarafından doğrulanan) görünümüdür.
type BodyJSON struct {
	CommandID       string `json:"command_id"`
	DeviceID        string `json:"device_id"`
	TenantID        string `json:"tenant_id"`
	Type            string `json:"type"`
	RequestedBy     string `json:"requested_by"`
	ApprovedBy      string `json:"approved_by"`
	CorrelationID   string `json:"correlation_id"`
	Sequence        uint64 `json:"sequence"`
	Nonce           string `json:"nonce"`
	IssuedAtNS      int64  `json:"issued_at_ns"`
	ExpiresAtNS     int64  `json:"expires_at_ns"`
	ParamsDigestHex string `json:"params_digest_hex"`
}

// EnvelopeCase, tek bir komut zarfı doğrulama vektörüdür.
type EnvelopeCase struct {
	Name string `json:"name"`
	Doc  string `json:"doc"`
	// DeviceID, DOĞRULAYANIN kendi kimliğidir; gövdedeki device_id buna eşit olmalıdır.
	DeviceID string `json:"device_id"`
	// NowNS: 0 = saat senkronsuz.
	NowNS int64 `json:"now_ns"`
	// MinSignatures: 0 = tipin varsayılanı (1).
	MinSignatures int `json:"min_signatures,omitempty"`
	// WireCommandID / WireType: telde gövde dışında taşınan değerler (boş = gövdeyle aynı).
	WireCommandID string `json:"wire_command_id,omitempty"`
	WireType      string `json:"wire_type,omitempty"`
	// Keys: doğrulayanın güvendiği anahtarlar (rol ve pencereyle).
	Keys   []KeyJSON   `json:"keys"`
	DSSE   DSSEJSON    `json:"dsse"`
	Params []ParamJSON `json:"params"`
	// PayloadHex/PAEHex: gövde ve imzalanan PAE baytları. Body: gövde ayrıştırılabiliyorsa
	// çözülmüş görünüm. DigestHex: sha256(PAE) (beklenen envelope_digest).
	PayloadHex string    `json:"payload_hex"`
	PAEHex     string    `json:"pae_hex"`
	Body       *BodyJSON `json:"body,omitempty"`
	DigestHex  string    `json:"envelope_digest_hex"`
	// Expect: "ok" ya da cmdenvelope.Reason adı.
	Expect string `json:"expect"`
}

// ParamsCase, params kodlama vektörü: ya geçerli bir küme (Params + bayt/özet) ya da
// reddedilmesi gereken ham bayt (EncodedHex + Expect).
type ParamsCase struct {
	Name       string      `json:"name"`
	Params     []ParamJSON `json:"params,omitempty"`
	EncodedHex string      `json:"encoded_hex"`
	DigestHex  string      `json:"digest_hex,omitempty"`
	Expect     string      `json:"expect"`
}

// ParamMapCase, JSON/structpb sınırı: ham JSON nesnesi ParamsFromMap'e verilir.
type ParamMapCase struct {
	Name   string `json:"name"`
	JSON   string `json:"json"`
	Expect string `json:"expect"` // "ok" | "malformed_params"
}

// StatementJSON, güven bildirimi gövdesinin (imzasız) çözülmüş görünümüdür.
type StatementJSON struct {
	Epoch         uint64    `json:"epoch"`
	Keys          []KeyJSON `json:"keys"`
	RootThreshold uint32    `json:"root_threshold"`
	IssuedAtNS    int64     `json:"issued_at_ns"`
	MinVerifyMode uint32    `json:"min_verify_mode"`
	MinAgentBuild uint64    `json:"min_agent_build"`
}

// StepCase, bir senaryodaki tek ApplyStatementDSSE adımıdır. Başarılı adım yerel durumu
// ilerletir; başarısız adım durumu DEĞİŞTİRMEZ.
type StepCase struct {
	Name       string         `json:"name"`
	Doc        string         `json:"doc"`
	NowNS      int64          `json:"now_ns"`
	DSSE       DSSEJSON       `json:"dsse"`
	PayloadHex string         `json:"payload_hex"`
	Body       *StatementJSON `json:"body,omitempty"`
	Expect     string         `json:"expect"` // "ok" | Reason
	Mode       string         `json:"mode,omitempty"`
	EpochJump  bool           `json:"epoch_jump,omitempty"`
	EpochAfter uint64         `json:"epoch_after"`
}

// KeyCheckCase, senaryo sonunda yerel durumda bir anahtarın komut imzalamaya uygunluğu.
type KeyCheckCase struct {
	Name   string `json:"name"`
	KeyID  string `json:"keyid"`
	NowNS  int64  `json:"now_ns"`
	Expect string `json:"expect"` // "ok" | Reason
}

// ChainCheckCase, adı geçen adımların bildirimlerinden kurulan zincir dosyasının VerifyChain sonucu.
type ChainCheckCase struct {
	Name   string   `json:"name"`
	Steps  []string `json:"steps"`
	NowNS  int64    `json:"now_ns"`
	Expect string   `json:"expect"`
}

// ScenarioCase, pin kümesi + sıralı adımlar + sonuç denetimleri.
type ScenarioCase struct {
	Name        string           `json:"name"`
	Doc         string           `json:"doc"`
	PinsHex     []string         `json:"pins_hex"`
	Steps       []StepCase       `json:"steps"`
	KeyChecks   []KeyCheckCase   `json:"key_checks"`
	ChainChecks []ChainCheckCase `json:"chain_checks"`
}

// ---- dönüştürücüler (üretici ve denetleyici ORTAK kullanır) ----------------

// Entry, KeyJSON'u cmdenvelope.KeyEntry'ye çevirir.
func (k KeyJSON) Entry() (cmdenvelope.KeyEntry, error) {
	pub, err := hex.DecodeString(k.PubHex)
	if err != nil {
		return cmdenvelope.KeyEntry{}, err
	}
	var role cmdenvelope.KeyRole
	switch k.Role {
	case "ROOT":
		role = cmdenvelope.KeyRoleRoot
	case "COMMAND":
		role = cmdenvelope.KeyRoleCommand
	default:
		return cmdenvelope.KeyEntry{}, fmt.Errorf("bilinmeyen rol %q", k.Role)
	}
	return cmdenvelope.KeyEntry{KeyID: k.KeyID, Pub: pub, Role: role, NotBeforeNS: k.NotBeforeNS, NotAfterNS: k.NotAfterNS}, nil
}

// KeyToJSON, cmdenvelope.KeyEntry'yi KeyJSON'a çevirir.
func KeyToJSON(k cmdenvelope.KeyEntry) KeyJSON {
	role := "ROOT"
	if k.Role == cmdenvelope.KeyRoleCommand {
		role = "COMMAND"
	}
	return KeyJSON{KeyID: k.KeyID, PubHex: hex.EncodeToString(k.Pub), Role: role, NotBeforeNS: k.NotBeforeNS, NotAfterNS: k.NotAfterNS}
}

// Entries, KeyJSON listesini çevirir.
func Entries(ks []KeyJSON) ([]cmdenvelope.KeyEntry, error) {
	out := make([]cmdenvelope.KeyEntry, 0, len(ks))
	for _, k := range ks {
		e, err := k.Entry()
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// ToDSSE, DSSEJSON'u cmdenvelope.DSSE'ye çevirir.
func (j DSSEJSON) ToDSSE() (cmdenvelope.DSSE, error) {
	payload, err := base64.StdEncoding.DecodeString(j.Payload)
	if err != nil {
		return cmdenvelope.DSSE{}, err
	}
	d := cmdenvelope.DSSE{PayloadType: j.PayloadType, Payload: payload}
	for _, s := range j.Signatures {
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			return cmdenvelope.DSSE{}, err
		}
		d.Signatures = append(d.Signatures, cmdenvelope.DSSESignature{KeyID: s.KeyID, Sig: sig})
	}
	return d, nil
}

// DSSEToJSON, cmdenvelope.DSSE'yi DSSEJSON'a çevirir.
func DSSEToJSON(d cmdenvelope.DSSE) DSSEJSON {
	j := DSSEJSON{PayloadType: d.PayloadType, Payload: base64.StdEncoding.EncodeToString(d.Payload), Signatures: []DSSESigJSON{}}
	for _, s := range d.Signatures {
		j.Signatures = append(j.Signatures, DSSESigJSON{KeyID: s.KeyID, Sig: base64.StdEncoding.EncodeToString(s.Sig)})
	}
	return j
}

// ToParams, ParamJSON listesini çevirir.
func ToParams(ps []ParamJSON) []cmdenvelope.Param {
	var out []cmdenvelope.Param
	for _, p := range ps {
		out = append(out, cmdenvelope.Param{Key: p.Key, Value: p.Value, List: p.List, IsList: p.IsList})
	}
	return out
}

// ParamsToJSON, cmdenvelope.Param listesini çevirir.
func ParamsToJSON(ps []cmdenvelope.Param) []ParamJSON {
	out := []ParamJSON{}
	for _, p := range ps {
		out = append(out, ParamJSON{Key: p.Key, Value: p.Value, List: p.List, IsList: p.IsList})
	}
	return out
}

// Statement, StatementJSON'u (imzasız) cmdenvelope.Statement'a çevirir.
func (j StatementJSON) Statement() (cmdenvelope.Statement, error) {
	keys, err := Entries(j.Keys)
	if err != nil {
		return cmdenvelope.Statement{}, err
	}
	return cmdenvelope.Statement{
		Epoch: j.Epoch, Keys: keys, RootThreshold: j.RootThreshold, IssuedAtNS: j.IssuedAtNS,
		MinVerifyMode: j.MinVerifyMode, MinAgentBuild: j.MinAgentBuild,
	}, nil
}

// StatementToJSON, cmdenvelope.Statement'ın imzasız görünümünü döner.
func StatementToJSON(st cmdenvelope.Statement) StatementJSON {
	j := StatementJSON{
		Epoch: st.Epoch, RootThreshold: st.RootThreshold, IssuedAtNS: st.IssuedAtNS,
		MinVerifyMode: st.MinVerifyMode, MinAgentBuild: st.MinAgentBuild, Keys: []KeyJSON{},
	}
	for _, k := range st.Keys {
		j.Keys = append(j.Keys, KeyToJSON(k))
	}
	return j
}

// Pubs, hex açık anahtar listesini çözer.
func Pubs(hexes []string) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, h := range hexes {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, err
		}
		out = append(out, ed25519.PublicKey(b))
	}
	return out, nil
}
