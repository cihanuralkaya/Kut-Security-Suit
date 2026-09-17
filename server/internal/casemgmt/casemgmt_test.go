package casemgmt

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// newCase, testler için küçük bir yardımcıdır.
func newCase(t *testing.T, s *MemStore, tenant, id string) Case {
	t.Helper()
	c, err := s.Create(Case{
		ID:       id,
		TenantID: tenant,
		Title:    "test vakası",
		Severity: SeverityHigh,
		Owner:    "alice",
	})
	if err != nil {
		t.Fatalf("Create hata: %v", err)
	}
	return c
}

func TestCreate(t *testing.T) {
	s := NewMemStore()

	t.Run("başarılı oluşturma OPEN ile başlar ve created girdisi yazar", func(t *testing.T) {
		c := newCase(t, s, "acme", "c-1")
		if c.Status != StatusOpen {
			t.Fatalf("durum = %q, beklenen %q", c.Status, StatusOpen)
		}
		if len(c.Timeline) != 1 || c.Timeline[0].Kind != KindCreated {
			t.Fatalf("zaman çizelgesi created ile başlamalı: %+v", c.Timeline)
		}
		if c.CreatedAt.IsZero() || c.UpdatedAt.IsZero() {
			t.Fatal("zaman damgaları ayarlanmalı")
		}
	})

	tests := []struct {
		name    string
		in      Case
		wantErr error
	}{
		{"kiracı boş", Case{ID: "x"}, ErrTenantRequired},
		{"id boş", Case{TenantID: "acme"}, ErrIDRequired},
		{"yinelenen id", Case{ID: "c-1", TenantID: "acme"}, ErrCaseExists},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.Create(tc.in); err != tc.wantErr {
				t.Fatalf("hata = %v, beklenen %v", err, tc.wantErr)
			}
		})
	}

	t.Run("severity varsayılanı MEDIUM", func(t *testing.T) {
		c, err := s.Create(Case{ID: "c-def", TenantID: "acme"})
		if err != nil {
			t.Fatal(err)
		}
		if c.Severity != SeverityMedium {
			t.Fatalf("severity = %q, beklenen %q", c.Severity, SeverityMedium)
		}
	})
}

func TestTransitions(t *testing.T) {
	tests := []struct {
		name  string
		from  Status
		to    Status
		valid bool
	}{
		{"open→investigating", StatusOpen, StatusInvestigating, true},
		{"open→closed", StatusOpen, StatusClosed, true},
		{"open→contained (geçersiz)", StatusOpen, StatusContained, false},
		{"investigating→contained", StatusInvestigating, StatusContained, true},
		{"investigating→open", StatusInvestigating, StatusOpen, true},
		{"contained→closed", StatusContained, StatusClosed, true},
		{"contained→investigating (regresyon)", StatusContained, StatusInvestigating, true},
		{"contained→open (geçersiz)", StatusContained, StatusOpen, false},
		{"closed→open (yeniden açma)", StatusClosed, StatusOpen, true},
		{"closed→investigating (geçersiz)", StatusClosed, StatusInvestigating, false},
		{"open→open (kendine, geçersiz)", StatusOpen, StatusOpen, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewMemStore()
			newCase(t, s, "acme", "c-1")
			// Vakayı istenen 'from' durumuna geçir (geçerli bir yol izleyerek).
			driveTo(t, s, "acme", "c-1", tc.from)

			before, _ := s.Get("acme", "c-1")
			c, err := s.Transition("acme", "c-1", "bob", tc.to, "not")

			if tc.valid {
				if err != nil {
					t.Fatalf("geçerli geçiş hata verdi: %v", err)
				}
				if c.Status != tc.to {
					t.Fatalf("durum = %q, beklenen %q", c.Status, tc.to)
				}
				last := c.Timeline[len(c.Timeline)-1]
				if last.Kind != KindTransition || last.Actor != "bob" {
					t.Fatalf("geçiş girdisi beklenirdi: %+v", last)
				}
				return
			}

			// Geçersiz: fail-closed olmalı.
			if err != ErrInvalidTransition {
				t.Fatalf("hata = %v, beklenen %v", err, ErrInvalidTransition)
			}
			after, _ := s.Get("acme", "c-1")
			if after.Status != before.Status {
				t.Fatalf("durum değişmemeliydi: %q → %q", before.Status, after.Status)
			}
			if len(after.Timeline) != len(before.Timeline) {
				t.Fatal("geçersiz geçiş zaman çizelgesine yazmamalı")
			}
		})
	}

	t.Run("bilinmeyen hedef durum", func(t *testing.T) {
		s := NewMemStore()
		newCase(t, s, "acme", "c-1")
		if _, err := s.Transition("acme", "c-1", "bob", Status("BOGUS"), ""); err != ErrInvalidStatus {
			t.Fatalf("hata = %v, beklenen %v", err, ErrInvalidStatus)
		}
	})
}

// driveTo, vakayı OPEN'dan hedef duruma geçerli geçişlerle götürür.
func driveTo(t *testing.T, s *MemStore, tenant, id string, target Status) {
	t.Helper()
	paths := map[Status][]Status{
		StatusOpen:          {},
		StatusInvestigating: {StatusInvestigating},
		StatusContained:     {StatusInvestigating, StatusContained},
		StatusClosed:        {StatusClosed},
	}
	for _, step := range paths[target] {
		if _, err := s.Transition(tenant, id, "setup", step, "kurulum"); err != nil {
			t.Fatalf("kurulum geçişi %q hata: %v", step, err)
		}
	}
}

func TestAppendOnlyTimeline(t *testing.T) {
	s := NewMemStore()
	newCase(t, s, "acme", "c-1")

	// Her mutasyon tam olarak bir olay eklemeli.
	if _, err := s.Assign("acme", "c-1", "bob", "carol"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Attach("acme", "c-1", "bob", AttachMITRE, "T1059"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Transition("acme", "c-1", "bob", StatusInvestigating, ""); err != nil {
		t.Fatal(err)
	}
	c, err := s.AddEvent("acme", "c-1", CaseEvent{Actor: "bob", Note: "serbest not"})
	if err != nil {
		t.Fatal(err)
	}

	// created + assign + attach + transition + note = 5
	if len(c.Timeline) != 5 {
		t.Fatalf("zaman çizelgesi uzunluğu = %d, beklenen 5: %+v", len(c.Timeline), c.Timeline)
	}
	if c.Timeline[4].Kind != KindNote {
		t.Fatalf("son girdi note olmalı: %+v", c.Timeline[4])
	}

	// Dışa verilen kopyayı değiştirmek depodaki değişmez izi bozmamalı.
	c.Timeline[0].Note = "KURCALANDI"
	c.Timeline = append(c.Timeline, CaseEvent{Note: "sahte"})
	fresh, _ := s.Get("acme", "c-1")
	if len(fresh.Timeline) != 5 {
		t.Fatal("depo zaman çizelgesi dış değişiklikten etkilenmemeli")
	}
	if fresh.Timeline[0].Note == "KURCALANDI" {
		t.Fatal("değişmez girdi dışarıdan değiştirilebildi")
	}
}

func TestAttach(t *testing.T) {
	s := NewMemStore()
	newCase(t, s, "acme", "c-1")

	if _, err := s.Attach("acme", "c-1", "bob", AttachAsset, "host-7"); err != nil {
		t.Fatal(err)
	}
	// Yinelenen ekleme yeni girdi üretmemeli.
	c, err := s.Attach("acme", "c-1", "bob", AttachAsset, "host-7")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Assets) != 1 {
		t.Fatalf("assets yinelenmemeli: %v", c.Assets)
	}
	// created + ilk attach = 2 (ikinci attach yinelenen, yazmaz).
	if len(c.Timeline) != 2 {
		t.Fatalf("zaman çizelgesi = %d, beklenen 2", len(c.Timeline))
	}

	if _, err := s.Attach("acme", "c-1", "bob", AttachKind("bogus"), "x"); err != ErrUnknownAttachKind {
		t.Fatalf("hata = %v, beklenen %v", err, ErrUnknownAttachKind)
	}
}

func TestTenantIsolation(t *testing.T) {
	s := NewMemStore()
	newCase(t, s, "acme", "c-1")
	newCase(t, s, "acme", "c-2")
	newCase(t, s, "globex", "c-1") // aynı ham id, farklı kiracı

	acme, err := s.List("acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(acme) != 2 {
		t.Fatalf("acme vaka sayısı = %d, beklenen 2", len(acme))
	}

	globex, _ := s.List("globex")
	if len(globex) != 1 {
		t.Fatalf("globex vaka sayısı = %d, beklenen 1", len(globex))
	}

	// Bir kiracı, diğerinin vakasını görmemeli/değiştirememeli.
	if _, err := s.Get("globex", "c-2"); err != ErrCaseNotFound {
		t.Fatalf("çapraz-kiracı Get hata = %v, beklenen %v", err, ErrCaseNotFound)
	}
	if _, err := s.Transition("globex", "c-2", "x", StatusClosed, ""); err != ErrCaseNotFound {
		t.Fatalf("çapraz-kiracı Transition hata = %v, beklenen %v", err, ErrCaseNotFound)
	}

	// Kiracı normalizasyonu: boşluk/harf farkı aynı kiracıyı bulmalı.
	if _, err := s.Get("  ACME ", "c-1"); err != nil {
		t.Fatalf("normalize edilmiş kiracı bulunamadı: %v", err)
	}
}

func TestAllowedTargets(t *testing.T) {
	got := AllowedTargets(StatusOpen)
	want := []Status{StatusClosed, StatusInvestigating} // sıralı
	if len(got) != len(want) {
		t.Fatalf("hedef sayısı = %d, beklenen %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("hedef[%d] = %q, beklenen %q", i, got[i], want[i])
		}
	}
}

func TestConcurrency(t *testing.T) {
	s := NewMemStore()
	newCase(t, s, "acme", "c-1")

	const workers = 16
	const perWorker = 40

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				switch i % 3 {
				case 0:
					_, _ = s.AddEvent("acme", "c-1", CaseEvent{
						Actor: fmt.Sprintf("w%d", w),
						Kind:  KindNote,
						Note:  fmt.Sprintf("i%d", i),
					})
				case 1:
					_, _ = s.Assign("acme", "c-1", fmt.Sprintf("w%d", w), "owner")
				case 2:
					_, _ = s.Attach("acme", "c-1", "w", AttachEvidence,
						fmt.Sprintf("ev-%d-%d", w, i))
				}
			}
		}(w)
	}
	wg.Wait()

	c, err := s.Get("acme", "c-1")
	if err != nil {
		t.Fatal(err)
	}
	// created(1) + tüm mutasyonlar (her biri ekler; yinelenen evidence yoktur).
	if len(c.Timeline) != workers*perWorker+1 {
		t.Fatalf("zaman çizelgesi = %d, beklenen %d",
			len(c.Timeline), workers*perWorker+1)
	}
	// Zaman çizelgesi monoton azalmayan zaman damgalarıyla append-only olmalı.
	for i := 1; i < len(c.Timeline); i++ {
		if c.Timeline[i].At.Before(c.Timeline[i-1].At) {
			t.Fatalf("zaman çizelgesi sırası bozuk: %v < %v",
				c.Timeline[i].At, c.Timeline[i-1].At)
		}
	}
}

func TestInjectedClock(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tick := base
	s := NewMemStore()
	s.now = func() time.Time {
		tick = tick.Add(time.Second)
		return tick
	}
	c, err := s.Create(Case{ID: "c-1", TenantID: "acme", Owner: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if !c.CreatedAt.Equal(base.Add(time.Second)) {
		t.Fatalf("enjekte saat kullanılmadı: %v", c.CreatedAt)
	}
}
