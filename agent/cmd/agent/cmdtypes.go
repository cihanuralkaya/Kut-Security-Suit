package main

import (
	"kut.corp/suite/cmdenvelope"
	kutv1 "kut.corp/suite/gen/kut/v1"
)

// commandSpec, proto komut tipinin PAYLAŞILAN komut tablosundaki (cmdenvelope; sunucu
// ile aynı kaynak) tanımını döner. Tabloda olmayan/UNSPECIFIED tip → ok=false.
func commandSpec(t kutv1.Command_CommandType) (cmdenvelope.Spec, bool) {
	return cmdenvelope.LookupProto(t.String())
}

// commandProtected, bir komut tipinin İMZASIZ teslimde reddedilmesi gereken (korumalı)
// tip olup olmadığını döner. Karar sunucudaki ile aynı cmdenvelope.Protected tablosundan
// gelir; UNSPECIFIED/kayıtsız tip fail-closed olarak korumalı sayılır. W2-S6 doğrulayıcısı
// bu fonksiyonu kullanır; ajan/sunucu uyumu cmdtypes_test.go ile sabitlenmiştir.
func commandProtected(t kutv1.Command_CommandType) bool {
	spec, ok := commandSpec(t)
	if !ok {
		return true
	}
	return cmdenvelope.Protected(spec.Name)
}
