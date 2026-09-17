package rulesimport

import (
	"errors"
	"strings"
	"testing"

	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/model"
)

func TestConvert_BasicContent(t *testing.T) {
	line := `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET evil UA"; content:"BadAgent"; nocase; classtype:trojan-activity; sid:2001; rev:3; reference:url,example.com/x;)`
	r, err := Convert(line)
	if err != nil {
		t.Fatalf("çevrilemedi: %v", err)
	}
	if r.ID != "rulesimport:2001" || r.Name != "ET evil UA" || r.Version != "3.0.0" {
		t.Fatalf("meta yanlış: %+v", r)
	}
	if len(r.Contains) != 1 || r.Contains[0] != "BadAgent" {
		t.Fatalf("content→contains yanlış: %+v", r.Contains)
	}
	if r.Severity != "CRITICAL" { // trojan-activity
		t.Fatalf("classtype→severity yanlış: %s", r.Severity)
	}
	if len(r.References) != 1 || !strings.Contains(r.References[0], "example.com") {
		t.Fatalf("reference yanlış: %+v", r.References)
	}
}

func TestConvert_NegatedContent(t *testing.T) {
	line := `alert tcp any any -> any any (msg:"x"; content:"powershell"; content:!"-Signed"; sid:10;)`
	r, err := Convert(line)
	if err != nil {
		t.Fatalf("çevrilemedi: %v", err)
	}
	if len(r.Contains) != 1 || r.Contains[0] != "powershell" {
		t.Fatalf("pozitif content yanlış: %+v", r.Contains)
	}
	if len(r.Absent) != 1 || r.Absent[0] != "-Signed" {
		t.Fatalf("negatif content→absent yanlış: %+v", r.Absent)
	}
}

func TestConvert_SequenceWithin(t *testing.T) {
	// within varsa içerik SIRALI kabul edilir → Sequence + WithinBytes.
	line := `alert tcp any any -> any any (msg:"chain"; content:"cmd"; content:"download"; within:50; sid:11;)`
	r, err := Convert(line)
	if err != nil {
		t.Fatalf("çevrilemedi: %v", err)
	}
	if len(r.Sequence) != 2 || r.Sequence[0] != "cmd" || r.Sequence[1] != "download" {
		t.Fatalf("sequence yanlış: %+v", r.Sequence)
	}
	if r.WithinBytes != 50 {
		t.Fatalf("within_bytes yanlış: %d", r.WithinBytes)
	}
	if len(r.Contains) != 0 {
		t.Fatalf("sequence modunda contains boş olmalı: %+v", r.Contains)
	}
}

func TestConvert_Threshold(t *testing.T) {
	line := `alert tcp any any -> any 22 (msg:"ssh bf"; content:"failed"; threshold: type threshold, track by_src, count 5, seconds 60; sid:12;)`
	r, err := Convert(line)
	if err != nil {
		t.Fatalf("çevrilemedi: %v", err)
	}
	if r.Threshold == nil || r.Threshold.Count != 5 || r.Threshold.Seconds != 60 || r.Threshold.Track != "device" {
		t.Fatalf("threshold yanlış: %+v", r.Threshold)
	}
	// type limit → eşiğe çevrilmemeli.
	r2, _ := Convert(`alert tcp any any -> any any (msg:"x"; content:"y"; threshold: type limit, track by_src, count 1, seconds 60; sid:13;)`)
	if r2.Threshold != nil {
		t.Fatalf("type limit eşiğe çevrilmemeliydi: %+v", r2.Threshold)
	}
}

func TestConvert_Flowbits(t *testing.T) {
	s1 := `alert tcp any any -> any any (msg:"stage1"; content:"recon"; flowbits:set,recon_seen; sid:14;)`
	s2 := `alert tcp any any -> any any (msg:"stage2"; content:"dump"; flowbits:isset,recon_seen; sid:15;)`
	r1, _ := Convert(s1)
	r2, _ := Convert(s2)
	if r1.Bits == nil || len(r1.Bits.Set) != 1 || r1.Bits.Set[0] != "recon_seen" {
		t.Fatalf("flowbits:set yanlış: %+v", r1.Bits)
	}
	if r2.Bits == nil || len(r2.Bits.Require) != 1 || r2.Bits.Require[0] != "recon_seen" {
		t.Fatalf("flowbits:isset yanlış: %+v", r2.Bits)
	}
	// isnotset → RequireNot
	r3, _ := Convert(`alert tcp any any -> any any (msg:"stage0"; content:"x"; flowbits:isnotset,handled; sid:19;)`)
	if r3.Bits == nil || len(r3.Bits.RequireNot) != 1 || r3.Bits.RequireNot[0] != "handled" {
		t.Fatalf("flowbits:isnotset yanlış: %+v", r3.Bits)
	}
}

func TestConvert_PCRE(t *testing.T) {
	r, err := Convert(`alert tcp any any -> any any (msg:"re"; pcre:"/mimikatz|psexec/i"; sid:16;)`)
	if err != nil {
		t.Fatalf("çevrilemedi: %v", err)
	}
	if r.MessageRegex != "mimikatz|psexec" {
		t.Fatalf("pcre→regex yanlış: %q", r.MessageRegex)
	}
	// Go RE2 ile derlenemeyen pcre (backreference) → atlanmalı.
	_, err = Convert(`alert tcp any any -> any any (msg:"bad"; pcre:"/(a)\1/"; sid:17;)`)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("derlenemeyen pcre ErrUnsupported dönmeliydi: %v", err)
	}
}

func TestConvert_QuotedSemicolon(t *testing.T) {
	// İçerikteki kaçışlı ';' seçenek ayıracı sayılmamalı.
	r, err := Convert(`alert tcp any any -> any any (msg:"semi"; content:"a\;b"; sid:18;)`)
	if err != nil {
		t.Fatalf("çevrilemedi: %v", err)
	}
	if len(r.Contains) != 1 || r.Contains[0] != "a;b" {
		t.Fatalf("kaçışlı ; içerik yanlış: %+v", r.Contains)
	}
}

func TestConvert_RejectsAndSkips(t *testing.T) {
	if _, err := Convert("# comment"); !errors.Is(err, ErrNotRule) {
		t.Fatal("yorum ErrNotRule olmalı")
	}
	if _, err := Convert(`pass tcp any any -> any any (msg:"x"; content:"y"; sid:1;)`); !errors.Is(err, ErrUnsupported) {
		t.Fatal("pass eylemi ErrUnsupported olmalı")
	}
	if _, err := Convert(`alert tcp any any -> any any (msg:"empty"; nocase; sid:1;)`); !errors.Is(err, ErrEmptyRule) {
		t.Fatal("eşleşme koşulsuz kural ErrEmptyRule olmalı")
	}
}

func TestConvertMulti_FileAndEngine(t *testing.T) {
	file := `# ET örnek kuralları
alert tcp any any -> any any (msg:"r1"; content:"evilA"; sid:100;)
alert tcp any any -> any any (msg:"r2 multi"; \
  content:"evilB"; classtype:attempted-admin; sid:101;)
# yorum
alert tcp any any -> any any (msg:"dup"; content:"z"; sid:100;)
garbage line without parens
`
	rules, skips := ConvertMulti([]byte(file))
	if len(rules) != 2 {
		t.Fatalf("2 kural bekleniyordu, %d: %+v", len(rules), rules)
	}
	// Yinelenen sid atlanmalı (skip raporlanır).
	foundDup := false
	for _, s := range skips {
		if strings.Contains(s, "yinelenen id") {
			foundDup = true
		}
	}
	if !foundDup {
		t.Fatalf("yinelenen sid atlanmalıydı: %v", skips)
	}
	// Satır-devamı (\\) birleştirilmeli: r2 content'i yakalanmalı.
	if rules[1].Name != "r2 multi" || len(rules[1].Contains) != 1 {
		t.Fatalf("satır-devamı yanlış: %+v", rules[1])
	}
	// Çevrilen kurallar motor doğrulamasından geçmeli ve çalışmalı.
	e := detect.NewEngine(rules)
	if d := e.Evaluate(model.Event{Message: "contains evilA here", Severity: "LOW"}); len(d) != 1 {
		t.Fatalf("çevrilen kural eşleşmedi: %+v", d)
	}
}
