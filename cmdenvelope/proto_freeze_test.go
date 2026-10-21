package cmdenvelope

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"

	kutv1 "kut.corp/suite/gen/kut/v1"
)

// W2-S2 tel dondurma: proto alan numaraları ve türleri değişemez (her değişiklik bir
// ajan dağıtımı gerektirir). Tablo, tasarım 2.6'nın birebir karşılığıdır.
func TestProtoFieldNumbersFrozen(t *testing.T) {
	type f struct {
		name string
		num  protoreflect.FieldNumber
		kind protoreflect.Kind
	}
	msgs := []struct {
		md     protoreflect.MessageDescriptor
		fields []f
	}{
		{(&kutv1.Command{}).ProtoReflect().Descriptor(), []f{
			{"command_id", 1, protoreflect.StringKind}, {"type", 2, protoreflect.EnumKind}, {"params", 3, protoreflect.MessageKind},
			{"signature", 4, protoreflect.BytesKind}, {"nonce", 5, protoreflect.StringKind},
			{"issued_at_unix", 6, protoreflect.Int64Kind}, {"expires_at_unix", 7, protoreflect.Int64Kind},
			{"issued_by", 8, protoreflect.StringKind},
			{"tenant_id", 9, protoreflect.StringKind}, {"envelope_version", 10, protoreflect.Uint32Kind},
			{"key_id", 11, protoreflect.StringKind}, {"correlation_id", 12, protoreflect.StringKind},
			{"sequence", 13, protoreflect.Uint64Kind}, {"approved_by", 14, protoreflect.StringKind},
			{"extra_signatures", 15, protoreflect.MessageKind},
		}},
		{(&kutv1.CommandSignature{}).ProtoReflect().Descriptor(), []f{{"key_id", 1, protoreflect.StringKind}, {"signature", 2, protoreflect.BytesKind}}},
		{(&kutv1.CommandResult{}).ProtoReflect().Descriptor(), []f{
			{"command_id", 1, protoreflect.StringKind}, {"status", 2, protoreflect.EnumKind}, {"detail", 3, protoreflect.StringKind},
			{"command_type", 4, protoreflect.EnumKind}, {"envelope_digest", 5, protoreflect.BytesKind},
		}},
		{(&kutv1.TrustStatement{}).ProtoReflect().Descriptor(), []f{
			{"epoch", 1, protoreflect.Uint64Kind}, {"keys", 2, protoreflect.MessageKind}, {"root_threshold", 3, protoreflect.Uint32Kind},
			{"issued_at_ns", 4, protoreflect.Int64Kind}, {"min_verify_mode", 5, protoreflect.Uint32Kind},
			{"min_agent_build", 6, protoreflect.Uint64Kind}, {"signatures", 7, protoreflect.MessageKind},
		}},
		{(&kutv1.KeyEntry{}).ProtoReflect().Descriptor(), []f{
			{"key_id", 1, protoreflect.StringKind}, {"pubkey", 2, protoreflect.BytesKind}, {"role", 3, protoreflect.EnumKind},
			{"not_before_ns", 4, protoreflect.Int64Kind}, {"not_after_ns", 5, protoreflect.Int64Kind},
		}},
		{(&kutv1.TrustSignature{}).ProtoReflect().Descriptor(), []f{{"key_id", 1, protoreflect.StringKind}, {"signature", 2, protoreflect.BytesKind}}},
		{(&kutv1.TenantBinding{}).ProtoReflect().Descriptor(), []f{{"tenant_id", 1, protoreflect.StringKind}}},
		{(&kutv1.EnrollResponse{}).ProtoReflect().Descriptor(), []f{
			{"device_id", 1, protoreflect.StringKind}, {"client_cert_pem", 2, protoreflect.BytesKind}, {"ca_chain_pem", 3, protoreflect.BytesKind},
			{"cert_not_after", 4, protoreflect.MessageKind}, {"command_trust", 5, protoreflect.MessageKind}, {"tenant_binding", 6, protoreflect.MessageKind},
		}},
		{(&kutv1.HeartbeatRequest{}).ProtoReflect().Descriptor(), []f{
			{"binary_hash", 5, protoreflect.StringKind}, {"acked_command_ids", 6, protoreflect.StringKind}, {"command_results", 7, protoreflect.MessageKind},
			{"trust_epoch", 8, protoreflect.Uint64Kind}, {"capabilities", 9, protoreflect.StringKind}, {"agent_build", 10, protoreflect.Uint64Kind},
		}},
		{(&kutv1.HeartbeatResponse{}).ProtoReflect().Descriptor(), []f{
			{"server_time", 1, protoreflect.MessageKind}, {"pending_commands", 4, protoreflect.MessageKind},
			{"trust_statements", 5, protoreflect.MessageKind}, {"tenant_binding", 6, protoreflect.MessageKind},
		}},
	}
	for _, m := range msgs {
		for _, want := range m.fields {
			fd := m.md.Fields().ByName(protoreflect.Name(want.name))
			if fd == nil {
				t.Errorf("%s.%s alanı yok", m.md.Name(), want.name)
				continue
			}
			if fd.Number() != want.num || fd.Kind() != want.kind {
				t.Errorf("%s.%s: no/tür %d/%v, dondurulmuş %d/%v", m.md.Name(), want.name, fd.Number(), fd.Kind(), want.num, want.kind)
			}
		}
	}

	// Sonraki dilimler için AYRILMIŞ numaralar: başka bir alan bunları kapamamalı.
	reserved := []struct {
		md       protoreflect.MessageDescriptor
		from, to protoreflect.FieldNumber
	}{
		{(&kutv1.PolicyBundle{}).ProtoReflect().Descriptor(), 5, 11},
		{(&kutv1.UpdateManifest{}).ProtoReflect().Descriptor(), 8, 12},
		{(&kutv1.AgentIdentity{}).ProtoReflect().Descriptor(), 5, 5},
	}
	for _, r := range reserved {
		for n := r.from; n <= r.to; n++ {
			if !r.md.ReservedRanges().Has(n) {
				t.Errorf("%s: %d numarası ayrılmamış", r.md.Name(), n)
			}
			if r.md.Fields().ByNumber(n) != nil {
				t.Errorf("%s: ayrılmış %d numarası kullanımda", r.md.Name(), n)
			}
		}
	}
	// KeyRole sayıları imza baytlarındaki U32(role) ile aynı olmalı.
	if kutv1.KeyRole_KEY_ROLE_ROOT != kutv1.KeyRole(KeyRoleRoot) || kutv1.KeyRole_KEY_ROLE_COMMAND != kutv1.KeyRole(KeyRoleCommand) {
		t.Error("KeyRole proto değerleri cmdenvelope.KeyRole ile ayrıştı")
	}
}

// toProto/fromProto yalnız test içindir (üretim bağdaştırıcıları S4/S6'da): telde cihaz
// kimliği YOKTUR; ajan kendi kimliğini koyar.
func envToProto(t *testing.T, e Envelope) *kutv1.Command {
	t.Helper()
	m := map[string]any{}
	for _, p := range e.Params {
		if p.IsList {
			l := make([]any, len(p.List))
			for i, s := range p.List {
				l[i] = s
			}
			m[p.Key] = l
		} else {
			m[p.Key] = p.Value
		}
	}
	st, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatal(err)
	}
	c := &kutv1.Command{
		CommandId: e.CommandID, Params: st, Signature: e.Signature, Nonce: e.Nonce,
		IssuedAtUnix: e.IssuedAtNS, ExpiresAtUnix: e.ExpiresAtNS, IssuedBy: e.RequestedBy,
		TenantId: e.TenantID, EnvelopeVersion: e.Version, KeyId: e.KeyID, CorrelationId: e.CorrelationID,
		Sequence: e.Sequence, ApprovedBy: e.ApprovedBy,
	}
	spec, _ := Lookup(e.Type)
	c.Type = kutv1.Command_CommandType(kutv1.Command_CommandType_value[spec.ProtoEnum])
	for _, x := range e.ExtraSignatures {
		c.ExtraSignatures = append(c.ExtraSignatures, &kutv1.CommandSignature{KeyId: x.KeyID, Signature: x.Sig})
	}
	return c
}

func envFromProto(t *testing.T, c *kutv1.Command) Envelope {
	t.Helper()
	ps, err := ParamsFromMap(c.GetParams().AsMap())
	if err != nil {
		t.Fatal(err)
	}
	e := Envelope{
		Version: c.EnvelopeVersion, KeyID: c.KeyId, CommandID: c.CommandId, TenantID: c.TenantId,
		Type: typeNameFromProto(c.Type), RequestedBy: c.IssuedBy, ApprovedBy: c.ApprovedBy,
		CorrelationID: c.CorrelationId, Sequence: c.Sequence, Nonce: c.Nonce,
		IssuedAtNS: c.IssuedAtUnix, ExpiresAtNS: c.ExpiresAtUnix, Params: ps, Signature: c.Signature,
	}
	for _, x := range c.ExtraSignatures {
		e.ExtraSignatures = append(e.ExtraSignatures, Signature{KeyID: x.KeyId, Sig: x.Signature})
	}
	return e
}

func typeNameFromProto(t kutv1.Command_CommandType) string {
	s, ok := LookupProto(t.String())
	if !ok {
		return ""
	}
	return s.Name
}

// Sunucu→proto→bayt→proto→ajan: imza, özet ve tüm alanlar sağlam geçer (N12 proto yarısı).
func TestEnvelopeSurvivesProtoRoundTrip(t *testing.T) {
	e := tEnv()
	e.Type = TypeWipe
	e.ApprovedBy = "admin:approver"
	e.Params = []Param{StringParam("path", "çğ/日本"), ListParam("args", "-a", "", "b c")}
	signed, err := SignV2(tKey("cmdA"), tDevice, e)
	if err != nil {
		t.Fatal(err)
	}
	co, _ := CoSignV2(tKey("cmdB"), tDevice, signed)
	signed.ExtraSignatures = []Signature{co}

	raw, err := proto.Marshal(envToProto(t, signed))
	if err != nil {
		t.Fatal(err)
	}
	var back kutv1.Command
	if err := proto.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	got := envFromProto(t, &back)
	v, err := VerifyV2(got, VerifyInput{DeviceID: tDevice, Keys: tCmdKeys("cmdA", "cmdB"), Now: tNow()})
	if err != nil {
		t.Fatalf("telden gelen zarf doğrulanmadı: %v", err)
	}
	if len(v.KeyIDs) != 2 {
		t.Fatalf("iki imza beklenirdi: %v", v.KeyIDs)
	}
	// Başka bir cihazın kimliğiyle doğrulanamaz (cihaz kimliği telde yok).
	_, err = VerifyV2(got, VerifyInput{DeviceID: tDevice2, Keys: tCmdKeys("cmdA", "cmdB"), Now: tNow()})
	wantReason(t, err, ReasonBadSignature)
}
