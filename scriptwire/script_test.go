package scriptwire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildField, bir alanın beklenen uzunluk-önekli kodlamasını üretir (referans).
func buildField(f []byte) []byte {
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(f)))
	return append(lp[:], f...)
}

func TestFieldFraming(t *testing.T) {
	// Boş alan: yalnız 4 baytlık sıfır uzunluk.
	got := field(nil, nil)
	if !bytes.Equal(got, []byte{0, 0, 0, 0}) {
		t.Fatalf("boş alan framing yanlış: %v", got)
	}
	// Dolu alan: 4 bayt uzunluk + ham baytlar; mevcut dst'e eklenmeli.
	got = field([]byte{0xAA}, []byte("hi"))
	want := append([]byte{0xAA}, buildField([]byte("hi"))...)
	if !bytes.Equal(got, want) {
		t.Fatalf("alan framing yanlış: got=%v want=%v", got, want)
	}
}

func TestCanonicalBytesDeterministic(t *testing.T) {
	s := Script{
		Interpreter: "powershell",
		Body:        "Get-Process",
		Args:        []string{"-Name", "kutd"},
	}
	a := CanonicalBytes(s)
	b := CanonicalBytes(s)
	if !bytes.Equal(a, b) {
		t.Fatal("CanonicalBytes deterministik olmalı (aynı girdi → aynı bayt)")
	}
}

func TestCanonicalBytesFraming(t *testing.T) {
	s := Script{
		Interpreter: "sh",
		Body:        "echo hi",
		Args:        []string{"a", "bb"},
	}
	got := CanonicalBytes(s)

	var want []byte
	want = append(want, buildField([]byte(domainTag))...)
	want = append(want, buildField([]byte("sh"))...)
	want = append(want, buildField([]byte("echo hi"))...)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], 2)
	want = append(want, n[:]...)
	want = append(want, buildField([]byte("a"))...)
	want = append(want, buildField([]byte("bb"))...)

	if !bytes.Equal(got, want) {
		t.Fatalf("kanonik framing yanlış:\n got=%v\nwant=%v", got, want)
	}
	// Domain tag baştan gelmeli.
	if !bytes.HasPrefix(got, buildField([]byte(domainTag))) {
		t.Fatal("çıktı domain-tag alanıyla başlamalı")
	}
}

func TestCanonicalBytesEmptyArgs(t *testing.T) {
	s := Script{Interpreter: "cmd", Body: "dir", Args: nil}
	got := CanonicalBytes(s)

	var want []byte
	want = append(want, buildField([]byte(domainTag))...)
	want = append(want, buildField([]byte("cmd"))...)
	want = append(want, buildField([]byte("dir"))...)
	want = append(want, 0, 0, 0, 0) // arg sayısı = 0
	if !bytes.Equal(got, want) {
		t.Fatalf("boş-args framing yanlış:\n got=%v\nwant=%v", got, want)
	}
}

func TestCanonicalBytesSingleByteChangeFlips(t *testing.T) {
	base := Script{Interpreter: "bash", Body: "run", Args: []string{"x"}}

	// Gövdede tek bir bayt değişikliği çıktıyı değiştirmeli.
	mut := base
	mut.Body = "ruN"
	if bytes.Equal(CanonicalBytes(base), CanonicalBytes(mut)) {
		t.Fatal("gövdedeki tek bayt değişikliği çıktıyı değiştirmeliydi")
	}

	// Arg içinde tek bayt değişikliği.
	mut2 := base
	mut2.Args = []string{"y"}
	if bytes.Equal(CanonicalBytes(base), CanonicalBytes(mut2)) {
		t.Fatal("arg değişikliği çıktıyı değiştirmeliydi")
	}

	// Uzunluk-öneki çakışması olmamalı: ("ab","") vs ("a","b") ayrışmalı.
	s1 := Script{Interpreter: "sh", Body: "", Args: []string{"ab", ""}}
	s2 := Script{Interpreter: "sh", Body: "", Args: []string{"a", "b"}}
	if bytes.Equal(CanonicalBytes(s1), CanonicalBytes(s2)) {
		t.Fatal("uzunluk-öneki sınır belirsizliğini önlemeli (framing çakışması)")
	}
}

func TestCanonicalBytesMultiArg(t *testing.T) {
	s := Script{Interpreter: "node", Body: "console.log(1)", Args: []string{"--a", "--b", "--c"}}
	got := CanonicalBytes(s)
	// Arg sayısı alanı domain+interp+body alanlarından sonra gelir.
	off := len(buildField([]byte(domainTag))) +
		len(buildField([]byte("node"))) +
		len(buildField([]byte("console.log(1)")))
	count := binary.BigEndian.Uint32(got[off : off+4])
	if count != 3 {
		t.Fatalf("arg sayısı 3 kodlanmalıydı, %d", count)
	}
}
