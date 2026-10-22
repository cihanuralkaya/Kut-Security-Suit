package cmdenvelope

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// Bu dosya, sabit zayıf-anahtar listesini bağımsız bir math/big Edwards25519 aritmetiğiyle
// doğrular: listedeki her kodlama gerçekten küçük mertebeli bir noktayı kodlar ve 8 küçük
// mertebeli noktanın tüm kodlamaları (kanonik ve takma adlar) listededir.

var (
	fieldP  = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	curveD  = new(big.Int).Mod(new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), fieldP)), fieldP)
	sqrtM1  = new(big.Int).Exp(big.NewInt(2), new(big.Int).Div(new(big.Int).Sub(fieldP, big.NewInt(1)), big.NewInt(4)), fieldP)
	bigOne  = big.NewInt(1)
	pointID = [2]*big.Int{big.NewInt(0), big.NewInt(1)}
)

func fmod(a *big.Int) *big.Int { return new(big.Int).Mod(a, fieldP) }

func edAdd(p, q [2]*big.Int) [2]*big.Int {
	x1y2 := fmod(new(big.Int).Mul(p[0], q[1]))
	x2y1 := fmod(new(big.Int).Mul(q[0], p[1]))
	y1y2 := fmod(new(big.Int).Mul(p[1], q[1]))
	x1x2 := fmod(new(big.Int).Mul(p[0], q[0]))
	t := fmod(new(big.Int).Mul(curveD, fmod(new(big.Int).Mul(x1x2, y1y2))))
	x3 := fmod(new(big.Int).Mul(fmod(new(big.Int).Add(x1y2, x2y1)),
		new(big.Int).ModInverse(fmod(new(big.Int).Add(bigOne, t)), fieldP)))
	y3 := fmod(new(big.Int).Mul(fmod(new(big.Int).Add(y1y2, x1x2)),
		new(big.Int).ModInverse(fmod(new(big.Int).Sub(bigOne, t)), fieldP)))
	return [2]*big.Int{x3, y3}
}

// edDecode, 32 baytı (y mod p, işaret biti) noktaya çözer; nokta yoksa ok=false.
func edDecode(enc []byte) (pt [2]*big.Int, ok bool) {
	b := append([]byte(nil), enc...)
	sign := b[31] >> 7
	b[31] &= 0x7f
	for i, j := 0, 31; i < j; i, j = i+1, j-1 { // little → big endian
		b[i], b[j] = b[j], b[i]
	}
	y := fmod(new(big.Int).SetBytes(b))
	y2 := fmod(new(big.Int).Mul(y, y))
	u := fmod(new(big.Int).Sub(y2, bigOne))
	v := fmod(new(big.Int).Add(fmod(new(big.Int).Mul(curveD, y2)), bigOne))
	a := fmod(new(big.Int).Mul(u, new(big.Int).ModInverse(v, fieldP)))
	x := new(big.Int).Exp(a, new(big.Int).Div(new(big.Int).Add(fieldP, big.NewInt(3)), big.NewInt(8)), fieldP)
	if fmod(new(big.Int).Mul(x, x)).Cmp(a) != 0 {
		x = fmod(new(big.Int).Mul(x, sqrtM1))
	}
	if fmod(new(big.Int).Mul(x, x)).Cmp(a) != 0 {
		return pt, false
	}
	if x.Sign() != 0 && uint(x.Bit(0)) != uint(sign) {
		x = fmod(new(big.Int).Neg(x))
	}
	return [2]*big.Int{x, y}, true
}

// edEncode, noktanın kanonik kodlamasıdır.
func edEncode(p [2]*big.Int) [32]byte {
	var out [32]byte
	yb := p[1].Bytes() // big endian
	for i := 0; i < len(yb); i++ {
		out[i] = yb[len(yb)-1-i]
	}
	out[31] |= byte(p[0].Bit(0)) << 7
	return out
}

func samePoint(a, b [2]*big.Int) bool { return a[0].Cmp(b[0]) == 0 && a[1].Cmp(b[1]) == 0 }

// torsion8, mertebe-8 noktasının 8 katını (alt grubun tamamı) döner.
func torsion8(t *testing.T) [][2]*big.Int {
	t.Helper()
	g, ok := edDecode(weakPublicKeys[6][:]) // mertebe-8 üreteci
	if !ok {
		t.Fatal("listedeki mertebe-8 girdisi bir noktaya çözülmüyor")
	}
	cur := pointID
	var out [][2]*big.Int
	for k := 0; k < 8; k++ {
		out = append(out, cur)
		cur = edAdd(cur, g)
	}
	if !samePoint(cur, pointID) {
		t.Fatal("8 * üreteç kimlik değil: üreteç mertebe 8 değil")
	}
	return out
}

func TestWeakKeyList_EntriesAreSmallOrder(t *testing.T) {
	tors := torsion8(t)
	for i, e := range weakPublicKeys {
		if hex.EncodeToString(e[:]) == "" || len(e) != 32 {
			t.Fatalf("girdi %d boyutu bozuk", i)
		}
		pt, ok := edDecode(e[:])
		if !ok {
			t.Errorf("girdi %d (%x) eğri üzerinde bir noktaya çözülmüyor", i, e)
			continue
		}
		found := false
		for _, q := range tors {
			if samePoint(pt, q) {
				found = true
			}
		}
		if !found {
			t.Errorf("girdi %d (%x) küçük mertebeli bir nokta değil", i, e)
		}
	}
}

func TestWeakKeyList_Complete(t *testing.T) {
	tors := torsion8(t)
	inList := func(enc []byte) bool {
		for i := range weakPublicKeys {
			if hex.EncodeToString(weakPublicKeys[i][:]) == hex.EncodeToString(enc) {
				return true
			}
		}
		return false
	}
	want := map[string]bool{}
	add := func(enc [32]byte) {
		want[hex.EncodeToString(enc[:])] = true
	}
	for _, p := range tors {
		c := edEncode(p)
		add(c)
		if p[0].Sign() == 0 { // x = 0: işaret biti kurulu takma ad
			a := c
			a[31] |= 0x80
			add(a)
		}
		if p[1].Cmp(big.NewInt(19)) < 0 { // y + p hâlâ 255 bite sığar: y ≥ p takma adı
			for _, sign := range []byte{0, 0x80} {
				yp := new(big.Int).Add(p[1], fieldP)
				be := yp.Bytes()
				var a [32]byte
				for i := 0; i < len(be); i++ {
					a[i] = be[len(be)-1-i]
				}
				a[31] |= sign
				add(a)
			}
		}
	}
	for enc := range want {
		b, _ := hex.DecodeString(enc)
		if !inList(b) {
			t.Errorf("küçük mertebeli kodlama %s listede yok", enc)
		}
		if !IsWeakPublicKey(b) {
			t.Errorf("IsWeakPublicKey(%s) = false", enc)
		}
	}
	if len(want) != len(weakPublicKeys) {
		t.Errorf("liste %d girdi, hesaplanan küme %d", len(weakPublicKeys), len(want))
	}
}

func TestIsWeakPublicKey_RejectsNonCanonicalAndAcceptsNormal(t *testing.T) {
	// y ≥ p olan herhangi bir kodlama (küçük mertebeli olmasa da) reddedilir.
	nc, _ := hex.DecodeString("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	if !IsWeakPublicKey(nc) {
		t.Error("y = p+3 kodlaması reddedilmedi")
	}
	if !IsWeakPublicKey(nil) || !IsWeakPublicKey(make([]byte, 31)) || !IsWeakPublicKey(make([]byte, 33)) {
		t.Error("yanlış boyutlu anahtar zayıf sayılmadı")
	}
	for _, n := range []string{"a", "b", "c", "root", "cmd"} {
		if IsWeakPublicKey(tPub(n)) {
			t.Errorf("normal anahtar %q zayıf sayıldı", n)
		}
	}
	if err := ValidatePublicKey(tPub("a")); err != nil {
		t.Errorf("normal anahtar reddedildi: %v", err)
	}
	if err := ValidatePublicKey(weakPublicKeys[2][:]); err == nil {
		t.Error("kimlik noktası kabul edildi")
	}
}
