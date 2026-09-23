package aisec

// tool.go — AG-04: tool/MCP çağrısı allowlist'i (KUT-AI-SEC-004) + bilinmeyen sunucu
// deny-by-default (INV-AG-009). Bilinmeyen bir tool/MCP sunucusu, saldırganın agent'a
// kötü-niyetli araç enjekte etme (tool/context poisoning, MITRE ATLAS) vektörüdür.

import (
	"strings"
	"sync"
)

// Privileged, yetenek kümesinin HASSAS (privileged) sayılıp sayılmayacağını döner:
// credential.read veya external.write içeriyorsa privileged. Bilinmeyen tool bu tür bir
// agent için deny-by-default'tur (INV-AG-009).
func (c CapSet) Privileged() bool {
	return c.Allows(CapCredentialRead) || c.Allows(CapExternalWrite)
}

// ToolRegistry, onaylı (bilinen) tool/MCP sunucu kimliklerinin allowlist'idir.
// Eşzamanlı kullanım için güvenlidir.
type ToolRegistry struct {
	mu    sync.RWMutex
	known map[string]bool
}

// NewToolRegistry, verilen bilinen tool kimlikleriyle bir kayıt oluşturur.
func NewToolRegistry(ids ...string) *ToolRegistry {
	r := &ToolRegistry{known: make(map[string]bool, len(ids))}
	for _, id := range ids {
		r.Allow(id)
	}
	return r
}

// Allow, bir tool/MCP kimliğini allowlist'e ekler (onay).
func (r *ToolRegistry) Allow(id string) {
	id = strings.TrimSpace(id)
	if id == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.known[id] = true
}

// Known, tool'un allowlist'te olup olmadığını döner.
func (r *ToolRegistry) Known(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.known[strings.TrimSpace(id)]
}

// AuthorizeToolCall, INV-AG-009'u uygular: bilinen tool → ALLOW. Bilinmeyen tool +
// PRIVILEGED agent → DENY (deny-by-default). Bilinmeyen tool + privileged-olmayan agent
// → REQUIRE_HUMAN (insan gözden geçirmeden bilinmeyen araç kullanılmaz). `eff` delegation+
// tenant kesişiminden gelen ETKİN yetenek kümesidir (INV-AG-003).
func (r *ToolRegistry) AuthorizeToolCall(toolID string, eff CapSet) AGDecision {
	if r.Known(toolID) {
		return AGAllow
	}
	if eff.Privileged() {
		return AGDeny
	}
	return AGRequireHuman
}
