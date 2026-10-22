package cmdenvelope

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

// ---- yardımcılar -------------------------------------------------------------------

// identityKey: kimlik noktası (mertebe 1) kodlaması.
func identityKey() ed25519.PublicKey {
	k := make([]byte, 32)
	k[0] = 1
	return k
}

// forgedIdentitySig: A = kimlik, R = taban noktası, S = 1. Standart kütüphane bu imzayı HER
// ileti için geçerli sayar (küçük mertebeli açık anahtar).
func forgedIdentitySig() []byte {
	sig := make([]byte, 64)
	sig[0] = 0x58
	for i := 1; i < 32; i++ {
		sig[i] = 0x66
	}
	sig[32] = 1
	return sig
}

func tApprover(name string, nb, na int64) KeyEntry {
	k := tCmd(name, nb, na)
	k.Role = KeyRoleApprover
	return k
}

func nowAt(ns int64) time.Time { return time.Unix(0, ns) }

// ---- anahtar rolleri ----------------------------------------------------------------

func TestKeyRoles_ValuesAreFixed(t *testing.T) {
	if KeyRoleRoot != 1 || KeyRoleCommand != 2 || KeyRoleApprover != 3 {
		t.Fatalf("rol sayıları değişti: %d %d %d", KeyRoleRoot, KeyRoleCommand, KeyRoleApprover)
	}
}

func TestStatement_ApproverRole(t *testing.T) {
	st := tStmt(1, 1, tRoot("root1"), tCmd("cmdA", tBase, tCmdEnd), tApprover("appr", tBase, tCmdEnd))
	if err := st.Validate(); err != nil {
		t.Fatalf("onaylayan anahtarlı bildirim geçerli olmalı: %v", err)
	}
	body, err := CanonicalStatement(st)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseStatement(body)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, k := range back.Keys {
		if k.Role == KeyRoleApprover {
			found = true
		}
	}
	if !found {
		t.Fatal("onaylayan rolü gidiş-dönüşte kayboldu")
	}
	// not_after zorunlu.
	noEnd := tStmt(1, 1, tRoot("root1"), tApprover("appr", tBase, 0))
	wantReason(t, noEnd.Validate(), ReasonMalformedStatement)
}

// Bilinmeyen rol: bildirim TAMAMEN reddedilir (kısmen yorumlanmaz), imzalı olsa bile.
func TestStatement_UnknownRoleRejectedWhole(t *testing.T) {
	st := tStmt(1, 1, tRoot("root1"), tCmd("cmdA", tBase, tCmdEnd))
	body, err := CanonicalStatement(st)
	if err != nil {
		t.Fatal(err)
	}
	// cmdA'nın rol alanını (pubkey'den hemen sonraki U32) 4 yap; kök imzasını yeniden at.
	i := strings.Index(string(body), string(tPub("cmdA")))
	if i < 0 {
		t.Fatal("pubkey gövdede yok")
	}
	patched := append([]byte(nil), body...)
	patched[i+32+3] = 4
	_, perr := ParseStatement(patched)
	wantReason(t, perr, ReasonMalformedStatement)
	sig := mustSig(t, "root1", PayloadTypeTrust, patched)
	_, aerr := ApplyStatementDSSE(nil, DSSE{PayloadType: PayloadTypeTrust, Payload: patched, Signatures: []DSSESignature{sig}}, nil, tAt())
	wantReason(t, aerr, ReasonMalformedStatement)
}

func TestStatement_ApproverCannotSignStatements(t *testing.T) {
	st := tStmt(1, 1, tRoot("root1"), tApprover("appr", tBase, tCmdEnd))
	st = tSign(t, st, "appr")
	_, err := ApplyStatement(nil, st, nil, tAt())
	wantReason(t, err, ReasonSignerNotRoot)
}

func TestVerifyV2_ApproverSignatures(t *testing.T) {
	d := tSigned(t)
	d2, err := CoSign(tKey("appr"), d)
	if err != nil {
		t.Fatal(err)
	}
	keys := append(tCmdKeys("cmdA"), tApprover("appr", tBase-int64(time.Hour), tCmdEnd))
	verify := func(dd DSSE, min int, ks []KeyEntry) (Verified, error) {
		return VerifyV2(dd, tEnv().Params, VerifyInput{DeviceID: tDevice, Keys: ks, Now: tNow(), MinSignatures: min})
	}
	// İki imza: komut + onaylayan → MinSignatures=2 sağlanır.
	v, err := verify(d2, 2, keys)
	if err != nil || len(v.KeyIDs) != 2 {
		t.Fatalf("komut+onaylayan: %v %v", v.KeyIDs, err)
	}
	// Onaylayan imzası yokken MinSignatures=2 → yetersiz.
	_, err = verify(d, 2, keys)
	wantReason(t, err, ReasonInsufficientSignatures)
	// Tek imzalı komutta fazladan onaylayan imzası zararsızdır.
	if _, err := verify(d2, 1, keys); err != nil {
		t.Fatalf("fazladan onaylayan imzası kabulü bozdu: %v", err)
	}
	// Yalnız onaylayan imzası: KOMUT imzası olmadan kabul edilmez (eşik 1 bile olsa).
	onlyAppr := d
	onlyAppr.Signatures = []DSSESignature{mustSig(t, "appr", PayloadTypeCommand, d.Payload)}
	_, err = verify(onlyAppr, 1, keys)
	wantReason(t, err, ReasonInsufficientSignatures)
	// Aynı açık anahtar hem KOMUT hem ONAYLAYAN listelenirse belirsizlik fail-closed: ikisi de atılır.
	both := append(tCmdKeys("cmdA"), tApprover("cmdA", tBase-int64(time.Hour), tCmdEnd))
	_, err = verify(d, 1, both)
	wantReason(t, err, ReasonUnknownKey)
	// Onaylayan penceresi dışında: yetersiz imza (onaylayan sayılmaz), pencere nedeniyle key_expired değil
	// çünkü komut imzası geçerlidir.
	late := append(tCmdKeys("cmdA"), tApprover("appr", tBase+int64(time.Hour), tCmdEnd))
	_, err = verify(d2, 2, late)
	wantReason(t, err, ReasonInsufficientSignatures)
}

// ---- zayıf (küçük mertebeli) anahtarlar -----------------------------------------------

// Kimlik açık anahtar + sahte imza daha önce komut anahtarı olarak kabul edilirdi.
func TestWeakKey_IdentityKeyForgedSignatureRejected(t *testing.T) {
	d := tSigned(t)
	pub := identityKey()
	sig := forgedIdentitySig()
	if ed25519.Verify(pub, PAE(PayloadTypeCommand, d.Payload), sig) {
		t.Log("önkoşul: standart kütüphane kimlik anahtarı + sahte imzayı geçerli sayıyor")
	}
	forged := DSSE{PayloadType: PayloadTypeCommand, Payload: d.Payload,
		Signatures: []DSSESignature{{KeyID: KeyID(pub), Sig: sig}}}
	trusted := []KeyEntry{{KeyID: KeyID(pub), Pub: pub, Role: KeyRoleCommand, NotBeforeNS: tBase - int64(time.Hour), NotAfterNS: tCmdEnd}}
	_, err := VerifyV2(forged, tEnv().Params, VerifyInput{DeviceID: tDevice, Keys: trusted, Now: tNow()})
	wantReason(t, err, ReasonUnknownKey)
	// Onaylayan rolünde de aynı.
	trusted[0].Role = KeyRoleApprover
	_, err = VerifyV2(forged, tEnv().Params, VerifyInput{DeviceID: tDevice, Keys: trusted, Now: tNow()})
	wantReason(t, err, ReasonUnknownKey)
}

func TestWeakKey_StatementValidateRejectsEveryWeakEncoding(t *testing.T) {
	for i, w := range weakPublicKeys {
		pub := ed25519.PublicKey(append([]byte(nil), w[:]...))
		for _, role := range []KeyRole{KeyRoleRoot, KeyRoleCommand, KeyRoleApprover} {
			k := KeyEntry{KeyID: KeyID(pub), Pub: pub, Role: role}
			if role != KeyRoleRoot {
				k.NotBeforeNS, k.NotAfterNS = tBase, tCmdEnd
			}
			st := tStmt(1, 1, tRoot("root1"), k)
			if err := st.Validate(); ReasonOf(err) != ReasonMalformedStatement {
				t.Errorf("girdi %d rol %d: zayıf anahtar kabul edildi (%v)", i, role, err)
			}
		}
	}
}

// Kimlik anahtarı KÖK olarak listelenmiş + sahte imza: bildirim kabul edilmez.
func TestWeakKey_IdentityRootWithForgedSignatureRejected(t *testing.T) {
	pub := identityKey()
	st := tStmt(1, 1, KeyEntry{KeyID: KeyID(pub), Pub: pub, Role: KeyRoleRoot})
	st.Signatures = []DSSESignature{{KeyID: KeyID(pub), Sig: forgedIdentitySig()}}
	_, err := ApplyStatement(nil, st, nil, tAt())
	wantReason(t, err, ReasonMalformedStatement)
}

// Zayıf bir pin güven kümesine alınmaz: sahte imza pin kuralıyla kabul ettiremez.
func TestWeakKey_WeakPinIgnored(t *testing.T) {
	g := tStmt(1, 1, tRoot("root1"), tCmd("cmdA", tBase, tCmdEnd))
	body, err := CanonicalStatement(g)
	if err != nil {
		t.Fatal(err)
	}
	pub := identityKey()
	d := DSSE{PayloadType: PayloadTypeTrust, Payload: body, Signatures: []DSSESignature{{KeyID: KeyID(pub), Sig: forgedIdentitySig()}}}
	if _, aerr := ApplyStatementDSSE(nil, d, []ed25519.PublicKey{pub}, tAt()); aerr == nil {
		t.Fatal("zayıf pin ile sahte imza kabul edildi")
	}
}

// ---- cihaz kimliği ----------------------------------------------------------------------

func TestCanonicalDeviceID(t *testing.T) {
	got, err := CanonicalDeviceID("Dev-ICE_01.Acme")
	if err != nil || got != "dev-ice_01.acme" {
		t.Fatalf("ASCII katlama: %q %v", got, err)
	}
	if !ValidDeviceID(got) {
		t.Fatal("katlanmış kimlik kanonik değil")
	}
	if got, err := CanonicalDeviceID(tDevice); err != nil || got != tDevice {
		t.Fatalf("zaten kanonik kimlik değişti: %q %v", got, err)
	}
	kelvin, dotted := "Kut", "İstanbul"
	// Unicode-farkında dönüşüm bu girdileri sessizce ASCII'ye katlardı (tehlike gerçek); burada
	// yalnız belgelenir, kimlik türetmede KULLANILMAZ.
	t.Logf("strings.ToLower(%q)=%q, (%q)=%q", kelvin, strings.ToLower(kelvin), dotted, strings.ToLower(dotted))
	for name, raw := range map[string]string{
		"kelvin sign":      kelvin,
		"dotted capital I": dotted,
		"latin-1 letter":   "café",
		"empty":            "",
		"space":            "dev ice",
		"tab":              "dev\tice",
		"nul":              "dev\x00ice",
		"del":              "dev\x7fice",
		"too long":         strings.Repeat("a", MaxDeviceIDLen+1),
		"fullwidth":        "Ｄev",
	} {
		got, err := CanonicalDeviceID(raw)
		if err == nil {
			t.Errorf("%s: kabul edildi (%q)", name, got)
		} else if ReasonOf(err) != ReasonBadDeviceID {
			t.Errorf("%s: neden %q", name, ReasonOf(err))
		}
	}
	// Doğrulayanın kimliği Kelvin/İ ile kurulursa VerifyV2 reddeder.
	d := tSigned(t)
	_, verr := VerifyV2(d, tEnv().Params, VerifyInput{DeviceID: "Kut", Keys: tCmdKeys("cmdA"), Now: tNow()})
	wantReason(t, verr, ReasonBadDeviceID)
	_, verr = VerifyV2(d, tEnv().Params, VerifyInput{DeviceID: "İstanbul", Keys: tCmdKeys("cmdA"), Now: tNow()})
	wantReason(t, verr, ReasonBadDeviceID)
}

func TestVerifyV2_ExpectTenant(t *testing.T) {
	d := tSigned(t) // tenant "acme"
	in := func(tenant *string) VerifyInput {
		return VerifyInput{DeviceID: tDevice, Keys: tCmdKeys("cmdA"), Now: tNow(), ExpectTenant: tenant}
	}
	if _, err := VerifyV2(d, tEnv().Params, in(TenantIs("acme"))); err != nil {
		t.Fatalf("eşleşen kiracı reddedildi: %v", err)
	}
	if _, err := VerifyV2(d, tEnv().Params, in(nil)); err != nil {
		t.Fatalf("kiracı denetimi kapalıyken ret: %v", err)
	}
	for _, other := range []string{"other", "ACME", "acme ", "acm", ""} {
		_, err := VerifyV2(d, tEnv().Params, in(TenantIs(other)))
		if ReasonOf(err) != ReasonWrongTenant {
			t.Errorf("kiracı %q: neden %q (%v)", other, ReasonOf(err), err)
		}
	}
	// Platform kiracısı ("") beklenirken kiracılı zarf reddedilir; tersi de.
	e := tEnv()
	e.TenantID = ""
	plat, err := SignV2(tKey("cmdA"), tDevice, e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyV2(plat, e.Params, in(TenantIs(""))); err != nil {
		t.Fatalf("platform zarfı reddedildi: %v", err)
	}
	_, err = VerifyV2(plat, e.Params, in(TenantIs("acme")))
	wantReason(t, err, ReasonWrongTenant)
}

// ---- güven bildirimi zamanı ---------------------------------------------------------------

// Süresi dolmuş kök, kendi eski penceresine geriye tarihli bildirim imzalar.
func TestApplyStatement_BackdatedByExpiredRootRejected(t *testing.T) {
	h := int64(time.Hour)
	expiring := tRoot("root2")
	expiring.NotAfterNS = tBase + 50*h
	local := tStmt(1, 1, tRoot("root1"), expiring, tCmd("cmdA", tBase, tCmdEnd))
	local.IssuedAtNS = tBase + 100*h // root2 bu anda artık geçersiz
	now := nowAt(tBase + 101*h)

	forgedKeys := []KeyEntry{tRoot("root1"), expiring, tCmd("cmdA", tBase, tCmdEnd), tCmd("evil", tBase, tCmdEnd)}
	forged := Statement{Epoch: 2, Keys: forgedKeys, RootThreshold: 1, IssuedAtNS: tBase + 40*h}
	forged = tSign(t, forged, "root2") // root2 yalnızca KENDİ eski penceresinde geçerli
	_, err := ApplyStatement(&local, forged, nil, now)
	wantReason(t, err, ReasonBackdated)

	// Karşı örnek: aynı bildirim yerel bildirimin anında ise süresi dolmuş anahtar sayılmaz.
	atLocal := forged
	atLocal.IssuedAtNS = local.IssuedAtNS
	atLocal.Signatures = nil
	atLocal = tSign(t, atLocal, "root2")
	_, err = ApplyStatement(&local, atLocal, nil, now)
	wantReason(t, err, ReasonThresholdNotMet)

	// Eşit zaman damgası kabul edilir (geçerli kökle).
	equal := Statement{Epoch: 2, Keys: forgedKeys[:3], RootThreshold: 1, IssuedAtNS: local.IssuedAtNS}
	equal = tSign(t, equal, "root1")
	if _, err := ApplyStatement(&local, equal, nil, now); err != nil {
		t.Fatalf("eşit issued_at reddedildi: %v", err)
	}
	// Pin imzası geriye tarih denetiminden muaf (kurtarma yolu).
	pinned := Statement{Epoch: 5, Keys: forgedKeys[:3], RootThreshold: 1, IssuedAtNS: tBase + 10*h}
	pinned = tSign(t, pinned, "root1")
	acc, err := ApplyStatement(&local, pinned, tPins("root1"), now)
	if err != nil || acc.Mode != AcceptPin {
		t.Fatalf("pin imzalı geriye tarihli kurtarma: %v %v", acc.Mode, err)
	}
}

// Saat yokken gelecek tarihli bildirim kabul edilemez.
func TestApplyStatement_ZeroClockNeverAcceptsFutureStatement(t *testing.T) {
	d := int64(24 * time.Hour)
	far := Statement{
		Epoch: 1, RootThreshold: 1, IssuedAtNS: tBase + 3000*d,
		Keys: []KeyEntry{tRoot("root1"), tCmd("cmdA", tBase+3000*d, tBase+3090*d)},
	}
	far = tSign(t, far, "root1")
	_, err := ApplyStatement(nil, far, nil, time.Time{})
	wantReason(t, err, ReasonClockUnsynced)
	if !ReasonOf(err).Transient() {
		t.Fatal("clock_unsynced geçici olmalı")
	}
	// Saat varsa aynı bildirim not_yet_valid.
	_, err = ApplyStatement(nil, far, nil, nowAt(tBase))
	wantReason(t, err, ReasonNotYetValid)
	// Zincir kuralı da saat yokken kabul vermez.
	g := tGenesis(t)
	next := tSign(t, tStmt(2, 2, tRoot("root1"), tRoot("root2"), tRoot("root3"), tCmd("cmdA", tBase, tCmdEnd)), "root1", "root2")
	_, err = ApplyStatement(&g, next, nil, time.Time{})
	wantReason(t, err, ReasonClockUnsynced)
	// Pin imzası saat gerektirmez (pin, bildirimden bağımsız kök yetkisidir).
	pinned := tSign(t, tStmt(1, 1, tRoot("root1"), tCmd("cmdA", tBase, tCmdEnd)), "root1")
	acc, err := ApplyStatement(nil, pinned, tPins("root1"), time.Time{})
	if err != nil || acc.Mode != AcceptPin {
		t.Fatalf("saatsiz pin kabulü: %v %v", acc.Mode, err)
	}
	// Zincir dosyası doğrulaması da saatsiz kabul vermez.
	_, err = VerifyChain([]Statement{g}, nil, time.Time{})
	wantReason(t, err, ReasonClockUnsynced)
}

// ---- zincirde desteklenmeyen girdiler ------------------------------------------------------

func TestApplyChainDSSE_SkipsUnsupportedPayloadTypes(t *testing.T) {
	g := tGenesis(t)
	keys := []KeyEntry{tRoot("root1"), tRoot("root2"), tRoot("root3"), tCmd("cmdA", tBase, tCmdEnd), tCmd("cmdB", tBase, tCmdEnd)}
	s2 := tSign(t, tStmt(2, 2, keys...), "root1", "root3")
	d1, _ := g.DSSE()
	d2, _ := s2.DSSE()
	future := DSSE{PayloadType: "application/vnd.kut.trust.v3", Payload: []byte("opaque"), Signatures: d2.Signatures}
	other := DSSE{PayloadType: PayloadTypeCommand, Payload: d2.Payload, Signatures: d2.Signatures}

	res, err := ApplyChainDSSE(nil, []DSSE{d1, future, other, d2}, nil, tAt())
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied != 2 || res.State == nil || res.State.Epoch != 2 {
		t.Fatalf("uygulanan %d, durum %+v", res.Applied, res.State)
	}
	if len(res.Skipped) != 2 || res.Skipped[0].Index != 1 || res.Skipped[0].Reason != ReasonUnsupportedVersion ||
		res.Skipped[1].Index != 2 || res.Skipped[1].Reason != ReasonBadPayloadType {
		t.Fatalf("atlananlar: %+v", res.Skipped)
	}
	// Yalnız desteklenmeyen girdiler: durum değişmez, hata yok.
	res, err = ApplyChainDSSE(&g, []DSSE{future}, nil, tAt())
	if err != nil || res.State.Epoch != 1 || res.Applied != 0 || len(res.Skipped) != 1 {
		t.Fatalf("yalnız atlama: %+v %v", res, err)
	}
}

// Atlama epoch ilerletmez: atlanan halkaya bağlı sonraki v2 halka epoch kuralından reddedilir.
func TestApplyChainDSSE_SkipDoesNotAdvanceEpoch(t *testing.T) {
	g := tGenesis(t)
	keys := []KeyEntry{tRoot("root1"), tRoot("root2"), tRoot("root3"), tCmd("cmdA", tBase, tCmdEnd)}
	s3 := tSign(t, tStmt(3, 2, keys...), "root1", "root2")
	d1, _ := g.DSSE()
	d3, _ := s3.DSSE()
	future := DSSE{PayloadType: "application/vnd.kut.trust.v3", Payload: []byte("x"), Signatures: d3.Signatures}
	res, err := ApplyChainDSSE(nil, []DSSE{d1, future, d3}, nil, tAt())
	wantReason(t, err, ReasonEpochSkipped)
	if res.Applied != 1 || res.State.Epoch != 1 || len(res.Skipped) != 1 {
		t.Fatalf("durum: %+v", res)
	}
}

// Yük türü doğru ama içerik geçersiz ya da kabul edilemezse zincir orada durur.
func TestApplyChainDSSE_InvalidSupportedEntryStopsChain(t *testing.T) {
	g := tGenesis(t)
	keys := []KeyEntry{tRoot("root1"), tRoot("root2"), tRoot("root3"), tCmd("cmdA", tBase, tCmdEnd)}
	bad := tSign(t, tStmt(2, 2, keys...), "root1") // eşik 2, tek imza
	d1, _ := g.DSSE()
	dBad, _ := bad.DSSE()
	res, err := ApplyChainDSSE(nil, []DSSE{d1, dBad}, nil, tAt())
	wantReason(t, err, ReasonThresholdNotMet)
	if res.Applied != 1 || res.State.Epoch != 1 {
		t.Fatalf("durum: %+v", res)
	}
	garbage := DSSE{PayloadType: PayloadTypeTrust, Payload: []byte("junk"), Signatures: d1.Signatures}
	_, err = ApplyChainDSSE(nil, []DSSE{garbage}, nil, tAt())
	wantReason(t, err, ReasonMalformedStatement)
}
