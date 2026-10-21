package cmdenvelope

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

func tRoot(name string) KeyEntry {
	p := tPub(name)
	return KeyEntry{KeyID: KeyID(p), Pub: p, Role: KeyRoleRoot}
}

func tCmd(name string, nb, na int64) KeyEntry {
	p := tPub(name)
	return KeyEntry{KeyID: KeyID(p), Pub: p, Role: KeyRoleCommand, NotBeforeNS: nb, NotAfterNS: na}
}

func tSign(t *testing.T, st Statement, signers ...string) Statement {
	t.Helper()
	for _, s := range signers {
		var err error
		if st, err = SignStatement(tKey(s), st); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

func tStmt(epoch uint64, threshold uint32, keys ...KeyEntry) Statement {
	return Statement{Epoch: epoch, Keys: keys, RootThreshold: threshold, IssuedAtNS: tBase + int64(epoch)*int64(time.Hour)}
}

const tCmdEnd = tBase + int64(90*24*time.Hour)

// tGenesis: epoch 1, kökler r1,r2,r3 eşik 2, komut anahtarı cmdA; r1+r2 imzalı.
func tGenesis(t *testing.T) Statement {
	t.Helper()
	st := tStmt(1, 2, tRoot("root1"), tRoot("root2"), tRoot("root3"), tCmd("cmdA", tBase, tCmdEnd))
	return tSign(t, st, "root1", "root2")
}

func tPins(names ...string) []ed25519.PublicKey {
	var out []ed25519.PublicKey
	for _, n := range names {
		out = append(out, tPub(n))
	}
	return out
}

func tAt() time.Time { return time.Unix(0, tBase+int64(30*time.Hour)) }

func TestGenesisBootstrap(t *testing.T) {
	g := tGenesis(t)
	acc, err := ApplyStatement(nil, g, nil, tAt())
	if err != nil || acc.Mode != AcceptBootstrap {
		t.Fatalf("genesis: %v %v", acc.Mode, err)
	}
	// Kendi eşiğinin altında.
	one := tSign(t, tStmt(1, 2, tRoot("root1"), tRoot("root2"), tCmd("cmdA", tBase, tCmdEnd)), "root1")
	_, err = ApplyStatement(nil, one, nil, tAt())
	wantReason(t, err, ReasonThresholdNotMet)
	// Pin tanımlıyken kendinden imzalı ilk bildirim reddedilir (N116).
	_, err = ApplyStatement(nil, g, tPins("root3"), tAt())
	wantReason(t, err, ReasonPinRequired)
	// Pin imzalı genesis: eşik aranmaz, 1 pin imzası yeter.
	pinned := tSign(t, tStmt(1, 2, tRoot("root1"), tRoot("root2"), tCmd("cmdA", tBase, tCmdEnd)), "root1")
	acc, err = ApplyStatement(nil, pinned, tPins("root1"), tAt())
	if err != nil || acc.Mode != AcceptPin {
		t.Fatalf("pin imzalı genesis: %v %v", acc.Mode, err)
	}
}

func TestRotationChainHops(t *testing.T) {
	g := tGenesis(t)
	// Epoch 2: cmdB eklenir; r1+r3 (mevcut kök kümesinden eşik) imzalar.
	e2 := tSign(t, tStmt(2, 2, tRoot("root1"), tRoot("root2"), tRoot("root3"), tCmd("cmdA", tBase, tCmdEnd), tCmd("cmdB", tBase, tCmdEnd)), "root1", "root3")
	acc, err := ApplyStatement(&g, e2, nil, tAt())
	if err != nil || acc.Mode != AcceptChain || acc.EpochJump {
		t.Fatalf("hop 2: %+v %v", acc, err)
	}
	// Epoch 3: cmdA kaldırılır (kök imzalı kaldırma).
	e3 := tSign(t, tStmt(3, 2, tRoot("root1"), tRoot("root2"), tRoot("root3"), tCmd("cmdB", tBase, tCmdEnd)), "root2", "root3")
	if _, err := ApplyStatement(&e2, e3, nil, tAt()); err != nil {
		t.Fatalf("hop 3: %v", err)
	}
	// Eşik altı imza (N108).
	bad := tSign(t, tStmt(2, 2, tRoot("root1"), tRoot("root2"), tRoot("root3"), tCmd("cmdB", tBase, tCmdEnd)), "root1")
	_, err = ApplyStatement(&g, bad, nil, tAt())
	wantReason(t, err, ReasonThresholdNotMet)
	// Aynı kök iki kez listelenir: bir kez sayılır (N108).
	dup := tSign(t, tStmt(2, 2, tRoot("root1"), tRoot("root2"), tRoot("root3"), tCmd("cmdB", tBase, tCmdEnd)), "root1")
	dup.Signatures = append(dup.Signatures, dup.Signatures[0])
	_, err = ApplyStatement(&g, dup, nil, tAt())
	wantReason(t, err, ReasonThresholdNotMet)
	// Sahte imza (bir bit bozuk) sayılmaz.
	forged := tSign(t, tStmt(2, 2, tRoot("root1"), tRoot("root2"), tRoot("root3"), tCmd("cmdB", tBase, tCmdEnd)), "root1", "root2")
	forged.Signatures = append([]StatementSignature(nil), forged.Signatures...)
	forged.Signatures[1].Sig = append([]byte(nil), forged.Signatures[1].Sig...)
	forged.Signatures[1].Sig[0] ^= 1
	_, err = ApplyStatement(&g, forged, nil, tAt())
	wantReason(t, err, ReasonThresholdNotMet)
	// Epoch atlama pin imzası olmadan reddedilir (N109); tekrar/eski epoch (N110).
	skip := tSign(t, tStmt(4, 2, tRoot("root1"), tRoot("root2"), tRoot("root3"), tCmd("cmdB", tBase, tCmdEnd)), "root1", "root2")
	_, err = ApplyStatement(&g, skip, nil, tAt())
	wantReason(t, err, ReasonEpochSkipped)
	_, err = ApplyStatement(&e2, g, nil, tAt())
	wantReason(t, err, ReasonStaleEpoch)
	_, err = ApplyStatement(&g, g, nil, tAt())
	wantReason(t, err, ReasonStaleEpoch)
}

// N107: yalnız KOMUT anahtarı imzalayan bildirim reddedilir.
func TestCommandKeyCannotSignStatements(t *testing.T) {
	g := tGenesis(t)
	st := tStmt(2, 2, tRoot("root1"), tRoot("root2"), tRoot("root3"), tCmd("cmdA", tBase, tCmdEnd))
	st = tSign(t, st, "cmdA")
	_, err := ApplyStatement(&g, st, nil, tAt())
	wantReason(t, err, ReasonSignerNotRoot)
	// Bootstrap yolunda da: yalnız komut anahtarı imzası.
	cmdOnly := tSign(t, tStmt(1, 1, tRoot("root1"), tCmd("cmdA", tBase, tCmdEnd)), "cmdA")
	_, err = ApplyStatement(nil, cmdOnly, nil, tAt())
	wantReason(t, err, ReasonSignerNotRoot)
	// Kök imzası + ek komut imzası: komut imzası yok sayılır, eşik kökle sağlanır.
	mixed := tSign(t, tStmt(2, 2, tRoot("root1"), tRoot("root2"), tRoot("root3"), tCmd("cmdA", tBase, tCmdEnd)), "root1", "root2", "cmdA")
	if _, err := ApplyStatement(&g, mixed, nil, tAt()); err != nil {
		t.Fatalf("ek komut imzası engel olmamalı: %v", err)
	}
	// Komut imzası eşiği TAMAMLAMAZ.
	short := tSign(t, tStmt(2, 2, tRoot("root1"), tRoot("root2"), tRoot("root3"), tCmd("cmdA", tBase, tCmdEnd)), "root1", "cmdA")
	_, err = ApplyStatement(&g, short, nil, tAt())
	wantReason(t, err, ReasonThresholdNotMet)
}

// TUF kuralı: kök kümesi değişiyorsa yeni kümenin eşiği de imzalamalı.
func TestRootSetChangeNeedsNewQuorum(t *testing.T) {
	g := tGenesis(t)
	newSet := func() Statement {
		return tStmt(2, 2, tRoot("root1"), tRoot("root4"), tRoot("root5"), tCmd("cmdA", tBase, tCmdEnd))
	}
	// Eski eşik (r1,r2) var, yeni kümeden yalnız r1 → red.
	_, err := ApplyStatement(&g, tSign(t, newSet(), "root1", "root2"), nil, tAt())
	wantReason(t, err, ReasonThresholdNotMet)
	// Yeni kümeden eşik var, eski kümeden yalnız r1 → red.
	_, err = ApplyStatement(&g, tSign(t, newSet(), "root1", "root4"), nil, tAt())
	wantReason(t, err, ReasonThresholdNotMet)
	// İkisi de sağlanır.
	acc, err := ApplyStatement(&g, tSign(t, newSet(), "root1", "root2", "root4"), nil, tAt())
	if err != nil || acc.Mode != AcceptChain {
		t.Fatalf("kök değişimi: %v %v", acc.Mode, err)
	}
}

// N109: pin imzalı bildirim local'den büyük HER epoch'u kabul ettirir.
func TestPinSignedEpochJump(t *testing.T) {
	g := tGenesis(t)
	jump := tSign(t, tStmt(7, 1, tRoot("root4"), tCmd("cmdB", tBase, tCmdEnd)), "root1")
	acc, err := ApplyStatement(&g, jump, tPins("root1"), tAt())
	if err != nil || acc.Mode != AcceptPin || !acc.EpochJump {
		t.Fatalf("pin atlaması: %+v %v", acc, err)
	}
	// Pin yokken aynı bildirim (root1 yalnız eski kümede, yeni küme farklı) kabul edilmez.
	_, err = ApplyStatement(&g, jump, nil, tAt())
	wantReason(t, err, ReasonEpochSkipped)
	// Pin imzası olmayan atlama reddedilir (başka pin).
	_, err = ApplyStatement(&g, jump, tPins("root3"), tAt())
	wantReason(t, err, ReasonEpochSkipped)
	// Pin imzası bile epoch geriletemez.
	back := tSign(t, tStmt(1, 1, tRoot("root1"), tCmd("cmdB", tBase, tCmdEnd)), "root1")
	_, err = ApplyStatement(&g, back, tPins("root1"), tAt())
	wantReason(t, err, ReasonStaleEpoch)
	// Yerel durum yokken pin imzalı yüksek epoch kabul edilir.
	acc, err = ApplyStatement(nil, jump, tPins("root1"), tAt())
	if err != nil || acc.Mode != AcceptPin {
		t.Fatalf("local=nil pin: %v %v", acc.Mode, err)
	}
	// Pin kümesi bildirimden bağımsızdır: sunucu bildirimde pin kökünü düşürse de pin kalır (N74/N115).
	if _, err := ApplyStatement(&g, jump, tPins("root1", "root2"), tAt()); err != nil {
		t.Fatalf("çoklu pin: %v", err)
	}
}

// Süresi dolmuş kök anahtar imzası sayılmaz; komut anahtarı süresi zincirde denetlenir.
func TestExpiredKeys(t *testing.T) {
	g := tGenesis(t)
	// root2 penceresi bildirim issued_at'ından ÖNCE kapanır.
	r2 := tRoot("root2")
	r2.NotAfterNS = tBase + int64(30*time.Minute) // epoch 2 issued = tBase+2h
	st := tStmt(2, 2, tRoot("root1"), r2, tRoot("root3"), tCmd("cmdA", tBase, tCmdEnd))
	st = tSign(t, st, "root1", "root2")
	// g'deki root2 süresiz; yerel kökler g'den gelir → yerel root2 kullanılır ve geçerli.
	if _, err := ApplyStatement(&g, st, nil, tAt()); err != nil {
		t.Fatalf("yerel kümedeki süresiz root2 imzası geçerli olmalı: %v", err)
	}
	// Bunu yerel duruma alıp epoch 3'ü root2'ye (artık süresi dolmuş) imzalatırsak red.
	e3 := tSign(t, tStmt(3, 2, tRoot("root1"), r2, tRoot("root3"), tCmd("cmdA", tBase, tCmdEnd)), "root1", "root2")
	_, err := ApplyStatement(&st, e3, nil, tAt())
	wantReason(t, err, ReasonThresholdNotMet)
	// root3 ile tamamlayınca geçer.
	e3 = tSign(t, e3, "root3")
	if _, err := ApplyStatement(&st, e3, nil, tAt()); err != nil {
		t.Fatalf("root1+root3 yeter: %v", err)
	}
	// Henüz geçerli olmayan kök (not_before gelecek).
	r3 := tRoot("root3")
	r3.NotBeforeNS = tBase + int64(100*time.Hour)
	st2 := tSign(t, tStmt(2, 2, tRoot("root1"), tRoot("root2"), r3, tCmd("cmdA", tBase, tCmdEnd)), "root1", "root2")
	if _, err := ApplyStatement(&g, st2, nil, tAt()); err != nil {
		t.Fatalf("hop 2: %v", err)
	}
	e3b := tSign(t, tStmt(3, 2, tRoot("root1"), tRoot("root2"), r3, tCmd("cmdA", tBase, tCmdEnd)), "root1", "root3")
	_, err = ApplyStatement(&st2, e3b, nil, tAt())
	wantReason(t, err, ReasonThresholdNotMet)

	// Komut anahtarı süresi: ChainKeyValid.
	cur := tStmt(2, 2, tRoot("root1"), tRoot("root2"),
		tCmd("cmdA", tBase, tBase+int64(10*time.Hour)), tCmd("cmdB", tBase+int64(50*time.Hour), tCmdEnd))
	idA, idB := KeyID(tPub("cmdA")), KeyID(tPub("cmdB"))
	at := func(h int64) time.Time { return time.Unix(0, tBase+h*int64(time.Hour)) }
	if _, err := ChainKeyValid(cur, idA, at(5)); err != nil {
		t.Fatalf("cmdA geçerli: %v", err)
	}
	if _, err := ChainKeyValid(cur, idA, at(11)); ReasonOf(err) != ReasonKeyExpired {
		t.Fatalf("cmdA süresi dolmuş olmalı: %v", err)
	}
	if _, err := ChainKeyValid(cur, idB, at(5)); ReasonOf(err) != ReasonNotYetValid {
		t.Fatalf("cmdB henüz geçerli değil: %v", err)
	}
	if _, err := ChainKeyValid(cur, KeyID(tPub("evil")), at(5)); ReasonOf(err) != ReasonKeyNotInChain {
		t.Fatalf("evil zincirde yok: %v", err)
	}
	if _, err := ChainKeyValid(cur, KeyID(tPub("root1")), at(5)); ReasonOf(err) != ReasonKeyNotInChain {
		t.Fatalf("kök anahtar komut anahtarı değil: %v", err)
	}
	if _, err := ChainKeyValid(cur, idA, time.Time{}); ReasonOf(err) != ReasonClockUnsynced {
		t.Fatalf("saat yok: %v", err)
	}
}

func TestStatementFromFutureAndStale(t *testing.T) {
	g := tGenesis(t)
	_, err := ApplyStatement(nil, g, nil, time.Unix(0, g.IssuedAtNS-int64(time.Hour)))
	wantReason(t, err, ReasonNotYetValid)
	// Saat yoksa (senkronsuz) gelecek denetimi atlanır; imza kuralları yine uygulanır.
	if _, err := ApplyStatement(nil, g, nil, time.Time{}); err != nil {
		t.Fatalf("saatsiz bootstrap: %v", err)
	}
}

func TestFloorsOnlyRatchetUp(t *testing.T) {
	f := Floors{}
	f = f.Raise(Statement{MinVerifyMode: 2, MinAgentBuild: 500})
	f = f.Raise(Statement{MinVerifyMode: 1, MinAgentBuild: 100})
	if f.MinVerifyMode != 2 || f.MinAgentBuild != 500 {
		t.Fatalf("eşikler düştü: %+v", f)
	}
	f = f.Raise(Statement{MinVerifyMode: 2, MinAgentBuild: 900})
	if f.MinAgentBuild != 900 {
		t.Fatal("eşik yükselmedi")
	}
}

// N113: 5 halkalı zincirde 3. halka geçersiz → durum 2. halkada kalır.
func TestApplyChainStopsAtInvalidHop(t *testing.T) {
	keys := func() []KeyEntry {
		return []KeyEntry{tRoot("root1"), tRoot("root2"), tRoot("root3"), tCmd("cmdA", tBase, tCmdEnd)}
	}
	h1 := tSign(t, tStmt(1, 2, keys()...), "root1", "root2")
	h2 := tSign(t, tStmt(2, 2, keys()...), "root1", "root3")
	h3 := tSign(t, tStmt(3, 2, keys()...), "root1") // eşik altı
	h4 := tSign(t, tStmt(4, 2, keys()...), "root1", "root2")
	h5 := tSign(t, tStmt(5, 2, keys()...), "root2", "root3")
	cur, n, err := ApplyChain(nil, []Statement{h1, h2, h3, h4, h5}, nil, tAt())
	wantReason(t, err, ReasonThresholdNotMet)
	if n != 2 || cur == nil || cur.Epoch != 2 {
		t.Fatalf("durum 2. halkada kalmalı: n=%d cur=%v", n, cur)
	}
	// Kalan halkalar 3. halkadan yeniden denendiğinde (geçerli h3 ile) ilerler.
	h3ok := tSign(t, tStmt(3, 2, keys()...), "root1", "root2")
	cur, n, err = ApplyChain(cur, []Statement{h3ok, h4, h5}, nil, tAt())
	if err != nil || n != 3 || cur.Epoch != 5 {
		t.Fatalf("devam: n=%d cur=%v err=%v", n, cur, err)
	}
}

func TestVerifyChainAndActiveKey(t *testing.T) {
	keys := func(cmds ...KeyEntry) []KeyEntry {
		return append([]KeyEntry{tRoot("root1"), tRoot("root2"), tRoot("root3")}, cmds...)
	}
	h1 := tSign(t, tStmt(1, 2, keys(tCmd("cmdA", tBase, tCmdEnd))...), "root1", "root2")
	h2 := tSign(t, tStmt(2, 2, keys(tCmd("cmdA", tBase, tCmdEnd), tCmd("cmdB", tBase, tCmdEnd))...), "root1", "root3")
	cur, err := VerifyChain([]Statement{h1, h2}, nil, tAt())
	if err != nil || cur.Epoch != 2 {
		t.Fatalf("zincir: %v %v", cur.Epoch, err)
	}
	if err := ActiveKeyValid([]Statement{h1, h2}, nil, tPub("cmdB"), tAt()); err != nil {
		t.Fatalf("cmdB güncel zincirde geçerli: %v", err)
	}
	// Aktif anahtar yalnız eski epoch'ta olsaydı (cmdB epoch 1'de yok): epoch 1 zinciri → red.
	if err := ActiveKeyValid([]Statement{h1}, nil, tPub("cmdB"), tAt()); ReasonOf(err) != ReasonKeyNotInChain {
		t.Fatalf("cmdB epoch 1'de olmamalı: %v", err)
	}
	// Süresi dolmuş aktif anahtar.
	if err := ActiveKeyValid([]Statement{h1, h2}, nil, tPub("cmdA"), time.Unix(0, tCmdEnd+1)); ReasonOf(err) != ReasonKeyExpired {
		t.Fatalf("süre dolmuş: %v", err)
	}
	// Eksik epoch ve boş zincir.
	if _, err := VerifyChain([]Statement{h2}, nil, tAt()); ReasonOf(err) != ReasonChainIncomplete {
		t.Fatalf("epoch 1 eksik: %v", err)
	}
	if _, err := VerifyChain(nil, nil, tAt()); ReasonOf(err) != ReasonChainIncomplete {
		t.Fatalf("boş zincir: %v", err)
	}
	h3bad := tSign(t, tStmt(3, 2, keys(tCmd("cmdA", tBase, tCmdEnd))...), "root1")
	if _, err := VerifyChain([]Statement{h1, h2, h3bad}, nil, tAt()); ReasonOf(err) != ReasonThresholdNotMet {
		t.Fatalf("geçersiz halka: %v", err)
	}
	// Pin tanımlıyken epoch 1 pin imzalı olmalı.
	if _, err := VerifyChain([]Statement{h1, h2}, tPins("root3"), tAt()); ReasonOf(err) != ReasonPinRequired {
		t.Fatalf("pin zorunlu: %v", err)
	}
	if _, err := VerifyChain([]Statement{h1, h2}, tPins("root1"), tAt()); err != nil {
		t.Fatalf("pin imzalı genesis: %v", err)
	}
}

func TestStatementValidate(t *testing.T) {
	ok := func() Statement {
		return tStmt(1, 1, tRoot("root1"), tCmd("cmdA", tBase, tCmdEnd))
	}
	if err := ok().Validate(); err != nil {
		t.Fatal(err)
	}
	mod := map[string]func(*Statement){
		"epoch 0":               func(s *Statement) { s.Epoch = 0 },
		"issued 0":              func(s *Statement) { s.IssuedAtNS = 0 },
		"threshold 0":           func(s *Statement) { s.RootThreshold = 0 },
		"threshold > roots":     func(s *Statement) { s.RootThreshold = 2 },
		"mode 3":                func(s *Statement) { s.MinVerifyMode = 3 },
		"no keys":               func(s *Statement) { s.Keys = nil },
		"no root":               func(s *Statement) { s.Keys = s.Keys[1:] },
		"cmd without not_after": func(s *Statement) { s.Keys[1].NotAfterNS = 0 },
		"role 0":                func(s *Statement) { s.Keys[1].Role = 0 },
		"role 3":                func(s *Statement) { s.Keys[1].Role = 3 },
		"key id mismatch":       func(s *Statement) { s.Keys[1].KeyID = KeyID(tPub("evil")) },
		"short pub":             func(s *Statement) { s.Keys[1].Pub = s.Keys[1].Pub[:5] },
		"duplicate key":         func(s *Statement) { s.Keys = append(s.Keys, s.Keys[0]) },
		"window inverted":       func(s *Statement) { s.Keys[1].NotAfterNS = s.Keys[1].NotBeforeNS - 1 },
		"negative not_before":   func(s *Statement) { s.Keys[0].NotBeforeNS = -1 },
		"bad sig shape":         func(s *Statement) { s.Signatures = []StatementSignature{{KeyID: "zz", Sig: nil}} },
		"too many keys": func(s *Statement) {
			for i := 0; i < MaxStatementKeys; i++ {
				p := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(i + 1)}, 32)).Public().(ed25519.PublicKey)
				s.Keys = append(s.Keys, KeyEntry{KeyID: KeyID(p), Pub: p, Role: KeyRoleRoot})
			}
		},
	}
	for name, f := range mod {
		s := ok()
		s.Keys = append([]KeyEntry(nil), s.Keys...)
		f(&s)
		if err := s.Validate(); ReasonOf(err) != ReasonMalformedStatement {
			t.Errorf("%s: neden %q (%v)", name, ReasonOf(err), err)
		}
	}
}

func TestStatementCanonicalAndStrictParse(t *testing.T) {
	st := tGenesis(t)
	a, err := CanonicalStatement(st)
	if err != nil {
		t.Fatal(err)
	}
	// Anahtar giriş sırası kanonik baytları değiştirmez.
	rev := st
	rev.Keys = append([]KeyEntry(nil), st.Keys...)
	for i, j := 0, len(rev.Keys)-1; i < j; i, j = i+1, j-1 {
		rev.Keys[i], rev.Keys[j] = rev.Keys[j], rev.Keys[i]
	}
	b, _ := CanonicalStatement(rev)
	if !bytes.Equal(a, b) {
		t.Fatal("anahtar sırası kanonik baytları değiştirdi")
	}
	// İmza kanonik iletiye dahil değil.
	nosig := st
	nosig.Signatures = nil
	c, _ := CanonicalStatement(nosig)
	if !bytes.Equal(a, c) {
		t.Fatal("imzalar kanonik iletiye girdi")
	}
	got, err := ParseStatement(a)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := CanonicalStatement(got); !bytes.Equal(again, a) {
		t.Fatal("Parse→Canonical bayt-bayt aynı değil")
	}
	if _, err := ParseStatement(append(append([]byte(nil), a...), 0)); err == nil {
		t.Fatal("artık bayt kabul edildi")
	}
	for i := 0; i < len(a); i++ {
		if _, err := ParseStatement(a[:i]); err == nil {
			t.Fatalf("kısaltılmış bildirim (%d) kabul edildi", i)
		}
	}
	// Sırasız / yinelenen anahtar: elle kurulmuş bayt.
	build := func(ks ...KeyEntry) []byte {
		x := appendLP(nil, DomainTrustV2)
		x = appendU64(x, 1)
		x = appendU32(x, 1)
		x = appendI64(x, tBase)
		x = appendU32(x, 0)
		x = appendU64(x, 0)
		x = appendU32(x, uint32(len(ks)))
		for _, k := range ks {
			x = appendLP(x, k.KeyID)
			x = appendLPBytes(x, k.Pub)
			x = appendU32(x, uint32(k.Role))
			x = appendI64(x, k.NotBeforeNS)
			x = appendI64(x, k.NotAfterNS)
		}
		return x
	}
	k1, k2 := tRoot("root1"), tRoot("root2")
	if k1.KeyID > k2.KeyID {
		k1, k2 = k2, k1
	}
	if _, err := ParseStatement(build(k1, k2)); err != nil {
		t.Fatalf("sıralı kümeyi reddetti: %v", err)
	}
	if _, err := ParseStatement(build(k2, k1)); err == nil {
		t.Fatal("sırasız anahtarlar kabul edildi")
	}
	if _, err := ParseStatement(build(k1, k1)); err == nil {
		t.Fatal("yinelenen anahtar kabul edildi")
	}
	// Başka alan etiketi.
	env, _ := CanonicalV2(tDevice, tSigned(t))
	if _, err := ParseStatement(env); err == nil {
		t.Fatal("zarf baytları bildirim olarak ayrıştı")
	}
}

func TestSignStatementReplacesSameSigner(t *testing.T) {
	st := tStmt(1, 1, tRoot("root1"), tCmd("cmdA", tBase, tCmdEnd))
	st = tSign(t, st, "root1", "root1")
	if len(st.Signatures) != 1 {
		t.Fatalf("aynı imzacı tek kez bulunmalı: %d", len(st.Signatures))
	}
	if _, err := SignStatement(ed25519.PrivateKey{1}, st); err == nil {
		t.Fatal("kısa özel anahtar imzaladı")
	}
}
