package grpc

import (
	"testing"
	"time"

	"kut.corp/suite/server/internal/detbits"
)

// TestNewHandlerHasBitStore, constructor'ın bit deposunu daima kurduğunu doğrular.
func TestNewHandlerHasBitStore(t *testing.T) {
	h := NewAgentHandler(nil, nil, nil, nil, nil)
	if h.detbits == nil {
		t.Fatal("NewAgentHandler bit deposunu kurmalıydı")
	}
}

// TestMultiStageBitGating, ingest döngüsünün çok-aşamalı mantığını (ön-koşul
// Require + durum Set) handler'a takılı depo üzerinden doğrular: aşama-2, aşama-1
// biti kurulmadan geçmemeli; kurulduktan sonra geçmeli; TTL dolunca yine kapanmalı.
func TestMultiStageBitGating(t *testing.T) {
	h := NewAgentHandler(nil, nil, nil, nil, nil)
	clk := time.Unix(1_700_000_000, 0)
	h.SetBitStore(detbits.New(func() time.Time { return clk }))

	scope := scopeKey("device", "dev1", "")

	// Aşama-2 ön-koşulu (recon_seen) henüz yok → bloke.
	if h.detbits.AllSet(scope, []string{"recon_seen"}) {
		t.Fatal("aşama-1 görülmeden ön-koşul sağlanmamalı")
	}
	// Aşama-1 eşleşti → bit kur (ingest döngüsünün Set dalı).
	h.detbits.Set(scope, "recon_seen", 3600*time.Second)
	if !h.detbits.AllSet(scope, []string{"recon_seen"}) {
		t.Fatal("aşama-1 sonrası ön-koşul sağlanmalı")
	}
	// Farklı cihaz etkilenmemeli (kapsam izolasyonu).
	if h.detbits.AllSet(scopeKey("device", "dev2", ""), []string{"recon_seen"}) {
		t.Fatal("bit yalnız kurulduğu cihazda geçerli olmalı")
	}
	// TTL dolunca ön-koşul tekrar kapanmalı.
	clk = clk.Add(3601 * time.Second)
	if h.detbits.AllSet(scope, []string{"recon_seen"}) {
		t.Fatal("TTL dolunca ön-koşul kapanmalı")
	}
}

// TestRequireNotGating, RequireNot (isnotset) kapısını doğrular: bit kurulu
// DEĞİLKEN geçmeli, kurulunca bloke olmalı (ör. "zaten ele alındı" bayrağı).
func TestRequireNotGating(t *testing.T) {
	h := NewAgentHandler(nil, nil, nil, nil, nil)
	clk := time.Unix(1_700_000_000, 0)
	h.SetBitStore(detbits.New(func() time.Time { return clk }))
	scope := scopeKey("device", "dev1", "")

	// "handled" kurulu değil → NoneSet true (kural geçer).
	if !h.detbits.NoneSet(scope, []string{"handled"}) {
		t.Fatal("handled kurulu değilken RequireNot geçmeli")
	}
	// Bit kurulunca → NoneSet false (kural bloke).
	h.detbits.Set(scope, "handled", time.Hour)
	if h.detbits.NoneSet(scope, []string{"handled"}) {
		t.Fatal("handled kuruluyken RequireNot bloke etmeli")
	}
}
