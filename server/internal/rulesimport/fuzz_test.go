package rulesimport

import "testing"

// FuzzConvertMulti, IDS kural ayrıştırıcısının rastgele/kötü niyetli girdide
// (dış kaynaklı feed metni) panik ATMADIĞINI doğrular. Convert de ConvertMulti
// içinden çağrıldığından tek hedef yeterlidir.
func FuzzConvertMulti(f *testing.F) {
	f.Add([]byte(`alert tcp any any -> any any (msg:"x"; content:"evil"; sid:1;)`))
	f.Add([]byte(`alert http $HOME_NET any -> any any (msg:"y"; content:!"ok"; pcre:"/a|b/i"; threshold: type threshold, track by_src, count 5, seconds 60; flowbits:set,a; sid:2;)`))
	f.Add([]byte("# comment\nalert tcp any any -> any any (msg:\"z\"; content:\"a\\;b\"; \\\n content:\"c\"; within:20; sid:3;)"))
	f.Add([]byte(`alert (`))                         // dengesiz paren
	f.Add([]byte(`alert tcp any any -> any any ()`)) // boş seçenek
	f.Add([]byte(`pass tcp any any -> any any (msg:"p"; content:"x"; sid:4;)`))
	f.Add([]byte(`alert x (content:"\";\"; pcre:"/(unclosed";)`)) // bozuk tırnak/pcre
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ConvertMulti(data) // panik olmamalı
	})
}
