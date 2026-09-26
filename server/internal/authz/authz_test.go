package authz

import (
	"fmt"
	"testing"
	"time"

	"kut.corp/suite/server/internal/scope"
)

// checkRate, hits map'i tavanı aşınca süresi dolmuş anahtarları süpürmeli (bellek sızıntısı yok).
func TestCheckRateSweepsIdleKeys(t *testing.T) {
	old := rateKeyCap
	rateKeyCap = 3
	defer func() { rateKeyCap = old }()

	g := NewGateway(Policy{HighImpactPerMin: 100}) // yüksek sınır → hep izin ver, kaydet
	base := time.Now()
	g.now = func() time.Time { return base }

	for i := 0; i < 5; i++ { // 5 farklı principal → 5 boşta anahtar
		g.checkRate(Request{Requester: AI, Principal: fmt.Sprintf("p%d", i)})
	}
	if len(g.hits) != 5 {
		t.Fatalf("kurulum: 5 anahtar beklenir, %d", len(g.hits))
	}
	base = base.Add(2 * time.Minute) // tüm girdiler pencere dışına çıksın
	g.checkRate(Request{Requester: AI, Principal: "pNew"})
	// 5 bayat anahtar süpürülmeli; yalnız pNew kalmalı.
	if len(g.hits) != 1 {
		t.Fatalf("boşta anahtarlar süpürülmedi: %d anahtar kaldı", len(g.hits))
	}
}

func TestLowImpactBypassesGateway(t *testing.T) {
	g := NewGateway(DefaultPolicy())
	// passive_scan düşük-etkili → sayı/talepçi fark etmeksizin geçer.
	d := g.Authorize(Request{Requester: AI, Action: scope.ActionPassiveScan, TargetCount: 10_000})
	if !d.Allow {
		t.Fatalf("düşük-etkili op geçmeli: %+v", d)
	}
}

func TestHumanSoftBlastRadius(t *testing.T) {
	g := NewGateway(Policy{SoftBlastRadius: 3, HardAutonomousRadius: 1})

	// Tavanın altında → onaysız geçer.
	if d := g.Authorize(Request{Action: scope.ActionQuarantine, TargetCount: 3}); !d.Allow {
		t.Fatalf("tavandaki insan talebi geçmeli: %+v", d)
	}
	// Tavanın üstünde, onaysız → NeedApproval (kalıcı red DEĞİL).
	d := g.Authorize(Request{Action: scope.ActionQuarantine, TargetCount: 4})
	if d.Allow || !d.NeedApproval {
		t.Fatalf("tavan aşımı onay istemeli: %+v", d)
	}
	// Açık onayla → geçer.
	if d := g.Authorize(Request{Action: scope.ActionQuarantine, TargetCount: 4, Confirmed: true}); !d.Allow {
		t.Fatalf("onaylı insan talebi geçmeli: %+v", d)
	}
}

func TestAutonomousHardCapCannotBeConfirmed(t *testing.T) {
	g := NewGateway(Policy{SoftBlastRadius: 500, HardAutonomousRadius: 3})
	// AI/SOAR sert tavanı Confirmed ile bile AŞAMAZ → kalıcı red (NeedApproval değil).
	for _, r := range []Requester{AI, SOAR, Rule} {
		d := g.Authorize(Request{Requester: r, Action: scope.ActionQuarantine, TargetCount: 4, Confirmed: true})
		if d.Allow {
			t.Fatalf("%s sert tavanı aşmamalı: %+v", r, d)
		}
		if d.NeedApproval {
			t.Fatalf("%s aşımı insan onayı gerektirir (NeedApproval=false, kalıcı red): %+v", r, d)
		}
	}
	// Sert tavanda → geçer.
	if d := g.Authorize(Request{Requester: SOAR, Action: scope.ActionQuarantine, TargetCount: 3}); !d.Allow {
		t.Fatalf("sert tavandaki otonom talep geçmeli: %+v", d)
	}
}

func TestRateLimitTripAndRecover(t *testing.T) {
	g := NewGateway(Policy{SoftBlastRadius: 500, HardAutonomousRadius: 3, HighImpactPerMin: 2})
	now := time.Unix(1_700_000_000, 0)
	g.now = func() time.Time { return now }

	req := Request{Principal: "admin1", Action: scope.ActionQuarantine, TargetCount: 1}
	if d := g.Authorize(req); !d.Allow {
		t.Fatalf("1. op geçmeli: %+v", d)
	}
	if d := g.Authorize(req); !d.Allow {
		t.Fatalf("2. op geçmeli: %+v", d)
	}
	// 3. op aynı dakikada → rate-limit.
	if d := g.Authorize(req); d.Allow {
		t.Fatalf("3. op rate-limit'e takılmalı: %+v", d)
	}
	// 61 saniye sonra pencere kayar → yeniden geçer.
	now = now.Add(61 * time.Second)
	if d := g.Authorize(req); !d.Allow {
		t.Fatalf("pencere kaydıktan sonra geçmeli: %+v", d)
	}
	// Farklı principal ayrı bütçeye sahiptir.
	other := Request{Principal: "admin2", Action: scope.ActionQuarantine, TargetCount: 1}
	if d := g.Authorize(other); !d.Allow {
		t.Fatalf("farklı principal ayrı bütçe: %+v", d)
	}
}
