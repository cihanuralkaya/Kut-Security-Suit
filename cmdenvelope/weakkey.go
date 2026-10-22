package cmdenvelope

// Zayıf (küçük mertebeli) Ed25519 açık anahtarı reddi.
//
// Ed25519 eğrisinin 8 küçük mertebeli noktası vardır (mertebe 1, 2, 4, 8). Bu noktalardan biri
// açık anahtar olarak kullanılırsa kimlik noktası dâhil herhangi bir iletiye geçerli sayılan
// imzalar üretilebilir (örn. A = kimlik noktası, R = taban noktası, S = 1). Standart kütüphane
// bu anahtarları reddetmez; bu yüzden güven kümesine giren her anahtar burada denetlenir.
//
// Liste SABİTTİR: 8 küçük mertebeli noktanın kanonik kodlamaları ile bunların kanonik olmayan
// takma adları (y ≥ p kodlamaları ve x = 0 iken işaret biti kurulu kodlamalar). Ayrıca y ≥ p
// olan HER kodlama (küçük mertebeli olsun olmasın) reddedilir: kanonik üreticiler bunu asla
// üretmez.

import (
	"bytes"
	"crypto/ed25519"
)

// weakPublicKeys, reddedilen 32 baytlık kodlamalardır (küçük endian y, bit 255 = x'in işaret biti).
var weakPublicKeys = [][ed25519.PublicKeySize]byte{
	// y = 0: mertebe 4 (işaret biti 0 ve 1: iki farklı nokta)
	hex32("0000000000000000000000000000000000000000000000000000000000000000"),
	hex32("0000000000000000000000000000000000000000000000000000000000000080"),
	// y = 1: kimlik noktası, mertebe 1 (işaret biti kurulu: kanonik olmayan takma ad)
	hex32("0100000000000000000000000000000000000000000000000000000000000000"),
	hex32("0100000000000000000000000000000000000000000000000000000000000080"),
	// y = p-1: mertebe 2 (işaret biti kurulu: kanonik olmayan takma ad)
	hex32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	hex32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
	// mertebe 8: iki y değeri, her biri iki işaretle
	hex32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
	hex32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
	hex32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
	hex32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
	// y = p ve y = p+1 (0 ve 1'in kanonik olmayan takma adları), iki işaretle
	hex32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	hex32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
	hex32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	hex32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
}

func hex32(s string) (out [ed25519.PublicKeySize]byte) {
	for i := 0; i < ed25519.PublicKeySize; i++ {
		out[i] = unhex(s[2*i])<<4 | unhex(s[2*i+1])
	}
	return out
}

func unhex(c byte) byte {
	if c >= 'a' {
		return c - 'a' + 10
	}
	return c - '0'
}

// yNotCanonical, kodlanmış y'nin (bit 255 hariç) p = 2^255-19'a eşit ya da büyük olup
// olmadığını döner.
func yNotCanonical(pub []byte) bool {
	if pub[31]&0x7f != 0x7f {
		return false
	}
	for i := 1; i < 31; i++ {
		if pub[i] != 0xff {
			return false
		}
	}
	return pub[0] >= 0xed
}

// IsWeakPublicKey, pub'ın güven kümesine ALINMAMASI gereken bir Ed25519 açık anahtarı olup
// olmadığını döner: boyut yanlışsa, küçük mertebeli bir nokta kodluyorsa (kimlik dâhil) ya da
// kanonik olmayan bir y kodluyorsa true.
func IsWeakPublicKey(pub []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return true
	}
	if yNotCanonical(pub) {
		return true
	}
	for i := range weakPublicKeys {
		if bytes.Equal(pub, weakPublicKeys[i][:]) {
			return true
		}
	}
	return false
}

// ValidatePublicKey, bir açık anahtarın güven kümesine girmeye uygun olup olmadığını denetler
// (boyut ve zayıf anahtar reddi). Araçlar anahtar girdisini imzalamadan önce çağırmalıdır.
func ValidatePublicKey(pub []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return newErr(ReasonMalformedStatement, "açık anahtar boyutu %d (%d olmalı)", len(pub), ed25519.PublicKeySize)
	}
	if IsWeakPublicKey(pub) {
		return newErr(ReasonMalformedStatement, "zayıf (küçük mertebeli ya da kanonik olmayan) açık anahtar")
	}
	return nil
}
