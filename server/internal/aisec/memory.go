package aisec

// memory.go — AG-03: agent hafıza bütünlüğü (KUT-AI-SEC-005) + provenance zorunluluğu
// (INV-AG-006) + memory-poisoning taint yayılımı. Hafıza, agent'ın kararlarını etkileyen
// kalıcı bağlamdır; zehirlenmiş bir hafıza girdisi sonraki eylemleri sessizce yönlendirir.

import (
	"errors"
	"strings"
	"time"
)

// ErrNoProvenance, provenance'sız (yazar/hash eksik) hafıza yazımıdır (INV-AG-006).
var ErrNoProvenance = errors.New("aisec: hafıza yazımı provenance gerektirir (yazar + içerik hash'i)")

// MemoryRecord, bir agent hafıza girdisidir (KUT-AI-SEC-005). Provenance ZORUNLUDUR:
// kim yazdı (AuthorPrincipal), kaynağın güveni (SourceTrust), içeriği (ValueHash) ve
// bu girdiyi etkileyen zincir (InfluenceChain). TTL sonrası girdi güvenilmez.
type MemoryRecord struct {
	Key             string
	ValueHash       string // içerik özeti (bütünlük/değişmezlik denetimi)
	AuthorPrincipal string // yazan principal (insan/agent/servis) — nihai sorumluluk
	SourceTrust     TrustLevel
	InfluenceChain  []string // girdiyi etkileyen principal/context kimlikleri (causality)
	TTL             time.Duration
	WrittenAt       time.Time
}

// ValidateMemoryWrite, INV-AG-006'yı uygular: hafıza yazımı PROVENANCE gerektirir —
// AuthorPrincipal ve ValueHash boş olamaz. Provenance'sız yazım reddedilir (anonim/
// kaynaksız hafıza zehirlemesini engeller).
func ValidateMemoryWrite(r MemoryRecord) error {
	if strings.TrimSpace(r.AuthorPrincipal) == "" || strings.TrimSpace(r.ValueHash) == "" {
		return ErrNoProvenance
	}
	return nil
}

// Expired, hafıza girdisinin TTL'ini geçip geçmediğini döner. Süresi dolmuş girdi
// karar bağlamında kullanılmamalıdır (bayat/zehirli bağlamın kalıcılığını sınırlar).
func (r MemoryRecord) Expired(now time.Time) bool {
	if r.TTL <= 0 {
		return false
	}
	return !now.Before(r.WrittenAt.Add(r.TTL))
}

// ReadTrust, bir agent'ın bu hafıza girdisini okuduktan sonraki ETKİN güven düzeyini
// döner: girdinin SourceTrust'ı agent'a YAYILIR (en kirli kazanır, INV-AG-001). Böylece
// zehirlenmiş (tainted) hafıza okuyan agent tainted olur → sonraki exfil guard (AG-02,
// INV-AG-004) bunu yakalar. Bu, memory-poisoning → downstream-etki zincirinin veri-zemini.
func (r MemoryRecord) ReadTrust(agentTrust TrustLevel) TrustLevel {
	return PropagateTrust(agentTrust, r.SourceTrust)
}
