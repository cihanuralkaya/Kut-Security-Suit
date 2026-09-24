package tamperprotect

import (
	"strings"
	"testing"
)

func TestJoin(t *testing.T) {
	if got := join(nil); got != "yok" {
		t.Fatalf("boş liste 'yok' olmalı, %q", got)
	}
	if got := join([]string{}); got != "yok" {
		t.Fatalf("boş dilim 'yok' olmalı, %q", got)
	}
	if got := join([]string{"a"}); got != "a" {
		t.Fatalf("tek eleman, %q", got)
	}
	if got := join([]string{"a", "b", "c"}); got != "a, b, c" {
		t.Fatalf("çoklu birleştirme yanlış, %q", got)
	}
}

func TestAssessKernelEmptyName(t *testing.T) {
	// Çekirdek mevcut ama isim boş → özet "present" göstermeli.
	p := Assess(Defenses{}, true, "")
	if p.Level != "kernel" || !p.KernelDriver {
		t.Fatalf("çekirdek durumu yanlış: %+v", p)
	}
	if !strings.Contains(p.Summary, "present") {
		t.Fatalf("boş isimde özet 'present' içermeli: %q", p.Summary)
	}
	// Userland boş olduğundan özet 'yok' içermeli.
	if !strings.Contains(p.Summary, "yok") {
		t.Fatalf("çekirdek + boş userland özetinde 'yok' beklenirdi: %q", p.Summary)
	}
}

func TestAssessKernelWithUserland(t *testing.T) {
	// Çekirdek mevcut + karışık userland kümesi.
	p := Assess(Defenses{FIM: true, SignedOTA: true}, true, "kutflt")
	if p.Level != "kernel" {
		t.Fatalf("seviye kernel olmalı, %q", p.Level)
	}
	if len(p.Userland) != 2 {
		t.Fatalf("2 userland savunması beklenirdi, %v", p.Userland)
	}
	if !strings.Contains(p.Summary, "kutflt") {
		t.Fatalf("özet sürücü adını içermeli: %q", p.Summary)
	}
	if !strings.Contains(p.Summary, "file-integrity") || !strings.Contains(p.Summary, "signed-ota") {
		t.Fatalf("özet userland savunmalarını içermeli: %q", p.Summary)
	}
}

func TestAssessMixedUserlandSets(t *testing.T) {
	cases := []struct {
		name string
		d    Defenses
		want []string
	}{
		{"yalnız watchdog", Defenses{Watchdog: true}, []string{"watchdog"}},
		{"liveness+selfattest", Defenses{Liveness: true, SelfAttest: true}, []string{"dual-process-liveness", "self-attestation"}},
		{"fim+ota", Defenses{FIM: true, SignedOTA: true}, []string{"file-integrity", "signed-ota"}},
	}
	for _, c := range cases {
		p := Assess(c.d, false, "")
		if p.Level != "userland" {
			t.Errorf("%s: seviye userland olmalı, %q", c.name, p.Level)
		}
		if len(p.Userland) != len(c.want) {
			t.Errorf("%s: %v beklenirdi, %v", c.name, c.want, p.Userland)
			continue
		}
		for i := range c.want {
			if p.Userland[i] != c.want[i] {
				t.Errorf("%s: sıralı liste yanlış: %v (beklenen %v)", c.name, p.Userland, c.want)
				break
			}
		}
	}
}
