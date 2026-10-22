package cmdenvelope

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"

	kutv1 "kut.corp/suite/gen/kut/v1"
)

// Tel dondurma: proto alan numaraları ve türleri değişemez (her değişiklik bir ajan
// dağıtımı gerektirir).
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
			{"envelope", 9, protoreflect.MessageKind},
		}},
		{(&kutv1.DsseEnvelope{}).ProtoReflect().Descriptor(), []f{
			{"payload_type", 1, protoreflect.StringKind}, {"payload", 2, protoreflect.BytesKind}, {"signatures", 3, protoreflect.MessageKind},
		}},
		{(&kutv1.DsseSignature{}).ProtoReflect().Descriptor(), []f{{"keyid", 1, protoreflect.StringKind}, {"sig", 2, protoreflect.BytesKind}}},
		{(&kutv1.CommandResult{}).ProtoReflect().Descriptor(), []f{
			{"command_id", 1, protoreflect.StringKind}, {"status", 2, protoreflect.EnumKind}, {"detail", 3, protoreflect.StringKind},
			{"command_type", 4, protoreflect.EnumKind}, {"envelope_digest", 5, protoreflect.BytesKind},
		}},
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
	// Zarf alanları DSSE tipindedir (komut, enroll ve heartbeat yolunda aynı mesaj).
	for _, c := range []struct {
		md   protoreflect.MessageDescriptor
		name string
	}{
		{(&kutv1.Command{}).ProtoReflect().Descriptor(), "envelope"},
		{(&kutv1.EnrollResponse{}).ProtoReflect().Descriptor(), "command_trust"},
		{(&kutv1.HeartbeatResponse{}).ProtoReflect().Descriptor(), "trust_statements"},
	} {
		if got := c.md.Fields().ByName(protoreflect.Name(c.name)).Message().FullName(); got != "kut.v1.DsseEnvelope" {
			t.Errorf("%s.%s tipi %s, beklenen kut.v1.DsseEnvelope", c.md.Name(), c.name, got)
		}
	}
	// Sonraki sürümler için AYRILMIŞ numaralar: başka bir alan bunları kapamamalı.
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
}

// Test içi bağdaştırıcılar (üretim bağdaştırıcıları ayrı bileşenlerde): telde gövde DSSE
// zarfındadır; params Command.params (structpb) olarak ayrıca taşınır.
func cmdToProto(t *testing.T, d DSSE, params []Param, commandID, typeName string) *kutv1.Command {
	t.Helper()
	m := map[string]any{}
	for _, p := range params {
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
	spec, _ := Lookup(typeName)
	c := &kutv1.Command{
		CommandId: commandID, Params: st,
		Type:     kutv1.Command_CommandType(kutv1.Command_CommandType_value[spec.ProtoEnum]),
		Envelope: &kutv1.DsseEnvelope{PayloadType: d.PayloadType, Payload: d.Payload},
	}
	for _, s := range d.Signatures {
		c.Envelope.Signatures = append(c.Envelope.Signatures, &kutv1.DsseSignature{Keyid: s.KeyID, Sig: s.Sig})
	}
	return c
}

func cmdFromProto(t *testing.T, c *kutv1.Command) (DSSE, []Param) {
	t.Helper()
	ps, err := ParamsFromMap(c.GetParams().AsMap())
	if err != nil {
		t.Fatal(err)
	}
	d := DSSE{PayloadType: c.Envelope.PayloadType, Payload: c.Envelope.Payload}
	for _, s := range c.Envelope.Signatures {
		d.Signatures = append(d.Signatures, DSSESignature{KeyID: s.Keyid, Sig: s.Sig})
	}
	return d, ps
}

func typeNameFromProto(t kutv1.Command_CommandType) string {
	s, ok := LookupProto(t.String())
	if !ok {
		return ""
	}
	return s.Name
}

// Sunucu→proto→bayt→proto→ajan: imza, özet ve tüm alanlar sağlam geçer; tel command_id/tip
// gövdeyle çapraz denetlenir.
func TestEnvelopeSurvivesProtoRoundTrip(t *testing.T) {
	e := tEnv()
	e.Type = TypeWipe
	e.ApprovedBy = "admin:approver"
	e.Params = []Param{StringParam("path", "çğ/日本"), ListParam("args", "-a", "", "b c")}
	d, err := SignV2(tKey("cmdA"), tDevice, e)
	if err != nil {
		t.Fatal(err)
	}
	if d, err = CoSign(tKey("cmdB"), d); err != nil {
		t.Fatal(err)
	}
	raw, err := proto.Marshal(cmdToProto(t, d, e.Params, e.CommandID, e.Type))
	if err != nil {
		t.Fatal(err)
	}
	var back kutv1.Command
	if err := proto.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	got, ps := cmdFromProto(t, &back)
	in := VerifyInput{DeviceID: tDevice, Keys: tCmdKeys("cmdA", "cmdB"), Now: tNow(), MinSignatures: 2,
		WireCommandID: back.CommandId, WireType: typeNameFromProto(back.Type)}
	v, err := VerifyV2(got, ps, in)
	if err != nil {
		t.Fatalf("telden gelen zarf doğrulanmadı: %v", err)
	}
	if len(v.KeyIDs) != 2 {
		t.Fatalf("iki imza beklenirdi: %v", v.KeyIDs)
	}
	// Başka bir cihaz bu zarfı kabul etmez.
	in.DeviceID = tDevice2
	_, err = VerifyV2(got, ps, in)
	wantReason(t, err, ReasonWrongDevice)
	// Tel tipi değiştirilmişse (WIPE→LOCK gibi) gövdeyle çelişir.
	in.DeviceID = tDevice
	in.WireType = TypeLock
	_, err = VerifyV2(got, ps, in)
	wantReason(t, err, ReasonMalformedEnvelope)
}
