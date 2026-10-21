// Package vectors, komut zarfı v2 ve güven bildirimi için ALTIN VEKTÖR dosyasının
// (cmdenvelope/testdata/v2_vectors.json) şemasını ve deterministik üreticisini içerir.
//
// Vektörler SABİT tohumlardan üretilir (Ed25519 imzaları deterministiktir); dosya her
// çalıştırmada bayt-bayt aynı çıkar. Aynı JSON dosyasını ajan testleri de (W2-S6) okur:
// sunucu ve ajan aynı baytları üretip aynı kararı vermelidir. Dosyayı yeniden üretmek
// bir TEL DEĞİŞİKLİĞİDİR ve bilinçli yapılmalıdır:
//
//	go test ./cmdenvelope -run TestGoldenVectors -update
package vectors

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"kut.corp/suite/cmdenvelope"
)

// FormatVersion, vektör dosyası şemasının sürümüdür.
const FormatVersion = 1

// File, vektör dosyasının kökü.
type File struct {
	Format      int            `json:"format"`
	Description string         `json:"description"`
	Seeds       []SeedJSON     `json:"seeds"`
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
	KeyID   string `json:"key_id"`
}

// KeyJSON, güven bildirimindeki ya da güvenilen kümedeki bir anahtardır.
type KeyJSON struct {
	KeyID       string `json:"key_id"`
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

// SigJSON, bir imza.
type SigJSON struct {
	KeyID  string `json:"key_id"`
	SigHex string `json:"sig_hex"`
}

// EnvelopeJSON, telde taşınan zarf alanlarıdır (cihaz kimliği YOK).
type EnvelopeJSON struct {
	Version         uint32      `json:"envelope_version"`
	KeyID           string      `json:"key_id"`
	CommandID       string      `json:"command_id"`
	TenantID        string      `json:"tenant_id"`
	Type            string      `json:"type"`
	RequestedBy     string      `json:"requested_by"`
	ApprovedBy      string      `json:"approved_by"`
	CorrelationID   string      `json:"correlation_id"`
	Sequence        uint64      `json:"sequence"`
	Nonce           string      `json:"nonce"`
	IssuedAtNS      int64       `json:"issued_at_ns"`
	ExpiresAtNS     int64       `json:"expires_at_ns"`
	Params          []ParamJSON `json:"params"`
	SignatureHex    string      `json:"signature_hex"`
	ExtraSignatures []SigJSON   `json:"extra_signatures"`
}

// EnvelopeCase, tek bir zarf doğrulama vektörüdür.
type EnvelopeCase struct {
	Name string `json:"name"`
	Doc  string `json:"doc"`
	// DeviceID, DOĞRULAYANIN kendi kimliğidir (imza girdisine bu konur).
	DeviceID string `json:"device_id"`
	// NowNS: 0 = saat senkronsuz.
	NowNS int64 `json:"now_ns"`
	// Keys: doğrulayanın güvendiği anahtarlar (rol ve pencereyle).
	Keys     []KeyJSON    `json:"keys"`
	Envelope EnvelopeJSON `json:"envelope"`
	// CanonicalHex: imzanın kapsadığı bayt dizisi (kurulamıyorsa boş). ParamsDigestHex ve
	// DigestHex yalnız kanonik bayt kurulabiliyorsa dolu.
	CanonicalHex    string `json:"canonical_hex"`
	ParamsDigestHex string `json:"params_digest_hex"`
	DigestHex       string `json:"envelope_digest_hex"`
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

// StatementJSON, güven bildirimi.
type StatementJSON struct {
	Epoch         uint64    `json:"epoch"`
	Keys          []KeyJSON `json:"keys"`
	RootThreshold uint32    `json:"root_threshold"`
	IssuedAtNS    int64     `json:"issued_at_ns"`
	MinVerifyMode uint32    `json:"min_verify_mode"`
	MinAgentBuild uint64    `json:"min_agent_build"`
	Signatures    []SigJSON `json:"signatures"`
}

// StepCase, bir senaryodaki tek ApplyStatement adımıdır. Başarılı adım yerel durumu
// ilerletir; başarısız adım durumu DEĞİŞTİRMEZ.
type StepCase struct {
	Name         string        `json:"name"`
	Doc          string        `json:"doc"`
	NowNS        int64         `json:"now_ns"`
	Statement    StatementJSON `json:"statement"`
	CanonicalHex string        `json:"canonical_hex"`
	Expect       string        `json:"expect"` // "ok" | Reason
	Mode         string        `json:"mode,omitempty"`
	EpochJump    bool          `json:"epoch_jump,omitempty"`
	EpochAfter   uint64        `json:"epoch_after"`
}

// KeyCheckCase, senaryo sonunda yerel durumda bir anahtarın komut imzalamaya uygunluğu.
type KeyCheckCase struct {
	Name   string `json:"name"`
	KeyID  string `json:"key_id"`
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

// Envelope, EnvelopeJSON'u cmdenvelope.Envelope'a çevirir.
func (j EnvelopeJSON) Envelope() (cmdenvelope.Envelope, error) {
	sig, err := hex.DecodeString(j.SignatureHex)
	if err != nil {
		return cmdenvelope.Envelope{}, err
	}
	e := cmdenvelope.Envelope{
		Version: j.Version, KeyID: j.KeyID, CommandID: j.CommandID, TenantID: j.TenantID, Type: j.Type,
		RequestedBy: j.RequestedBy, ApprovedBy: j.ApprovedBy, CorrelationID: j.CorrelationID,
		Sequence: j.Sequence, Nonce: j.Nonce, IssuedAtNS: j.IssuedAtNS, ExpiresAtNS: j.ExpiresAtNS,
		Signature: sig,
	}
	for _, p := range j.Params {
		e.Params = append(e.Params, cmdenvelope.Param{Key: p.Key, Value: p.Value, List: p.List, IsList: p.IsList})
	}
	for _, x := range j.ExtraSignatures {
		s, err := hex.DecodeString(x.SigHex)
		if err != nil {
			return cmdenvelope.Envelope{}, err
		}
		e.ExtraSignatures = append(e.ExtraSignatures, cmdenvelope.Signature{KeyID: x.KeyID, Sig: s})
	}
	return e, nil
}

// EnvelopeToJSON, cmdenvelope.Envelope'u EnvelopeJSON'a çevirir.
func EnvelopeToJSON(e cmdenvelope.Envelope) EnvelopeJSON {
	j := EnvelopeJSON{
		Version: e.Version, KeyID: e.KeyID, CommandID: e.CommandID, TenantID: e.TenantID, Type: e.Type,
		RequestedBy: e.RequestedBy, ApprovedBy: e.ApprovedBy, CorrelationID: e.CorrelationID,
		Sequence: e.Sequence, Nonce: e.Nonce, IssuedAtNS: e.IssuedAtNS, ExpiresAtNS: e.ExpiresAtNS,
		SignatureHex: hex.EncodeToString(e.Signature), Params: []ParamJSON{}, ExtraSignatures: []SigJSON{},
	}
	for _, p := range e.Params {
		j.Params = append(j.Params, ParamJSON{Key: p.Key, Value: p.Value, List: p.List, IsList: p.IsList})
	}
	for _, x := range e.ExtraSignatures {
		j.ExtraSignatures = append(j.ExtraSignatures, SigJSON{KeyID: x.KeyID, SigHex: hex.EncodeToString(x.Sig)})
	}
	return j
}

// Statement, StatementJSON'u cmdenvelope.Statement'a çevirir.
func (j StatementJSON) Statement() (cmdenvelope.Statement, error) {
	keys, err := Entries(j.Keys)
	if err != nil {
		return cmdenvelope.Statement{}, err
	}
	st := cmdenvelope.Statement{
		Epoch: j.Epoch, Keys: keys, RootThreshold: j.RootThreshold, IssuedAtNS: j.IssuedAtNS,
		MinVerifyMode: j.MinVerifyMode, MinAgentBuild: j.MinAgentBuild,
	}
	for _, s := range j.Signatures {
		b, err := hex.DecodeString(s.SigHex)
		if err != nil {
			return cmdenvelope.Statement{}, err
		}
		st.Signatures = append(st.Signatures, cmdenvelope.StatementSignature{KeyID: s.KeyID, Sig: b})
	}
	return st, nil
}

// StatementToJSON, cmdenvelope.Statement'ı StatementJSON'a çevirir.
func StatementToJSON(st cmdenvelope.Statement) StatementJSON {
	j := StatementJSON{
		Epoch: st.Epoch, RootThreshold: st.RootThreshold, IssuedAtNS: st.IssuedAtNS,
		MinVerifyMode: st.MinVerifyMode, MinAgentBuild: st.MinAgentBuild,
		Keys: []KeyJSON{}, Signatures: []SigJSON{},
	}
	for _, k := range st.Keys {
		j.Keys = append(j.Keys, KeyToJSON(k))
	}
	for _, s := range st.Signatures {
		j.Signatures = append(j.Signatures, SigJSON{KeyID: s.KeyID, SigHex: hex.EncodeToString(s.Sig)})
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
