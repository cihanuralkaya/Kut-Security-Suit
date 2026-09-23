package aisec

import "testing"

// TestAuthorizeToolCall, INV-AG-009'u doğrular: bilinen tool ALLOW; bilinmeyen tool +
// privileged agent DENY (deny-by-default); bilinmeyen + privileged-olmayan REQUIRE_HUMAN.
func TestAuthorizeToolCall(t *testing.T) {
	reg := NewToolRegistry("mcp.files", "mcp.search")
	priv := CapSet{CapCredentialRead: true} // privileged
	basic := CapSet{"incident.read": true}  // privileged değil

	if got := reg.AuthorizeToolCall("mcp.files", priv); got != AGAllow {
		t.Errorf("bilinen tool ALLOW olmalı: %s", got)
	}
	if got := reg.AuthorizeToolCall("mcp.evil", priv); got != AGDeny {
		t.Errorf("bilinmeyen tool + privileged agent DENY olmalı (INV-AG-009): %s", got)
	}
	if got := reg.AuthorizeToolCall("mcp.evil", basic); got != AGRequireHuman {
		t.Errorf("bilinmeyen tool + basic agent REQUIRE_HUMAN olmalı: %s", got)
	}
}

// TestToolRegistryAllowAndKnown, allowlist ekleme + boş/whitespace kimlik davranışını
// doğrular.
func TestToolRegistryAllowAndKnown(t *testing.T) {
	reg := NewToolRegistry()
	if reg.Known("x") {
		t.Fatal("boş kayıt hiçbir tool'u bilmemeli")
	}
	reg.Allow("  mcp.x  ")
	if !reg.Known("mcp.x") {
		t.Fatal("Allow sonrası tool bilinmeli (trim edilmiş)")
	}
	reg.Allow("   ") // boş → yok sayılır
	if reg.Known("") {
		t.Fatal("boş kimlik eklenmemeli")
	}
}

// TestCapSetPrivileged, hassas yeteneklerin privileged saydığını doğrular.
func TestCapSetPrivileged(t *testing.T) {
	if !(CapSet{CapCredentialRead: true}).Privileged() {
		t.Error("credential.read privileged olmalı")
	}
	if !(CapSet{CapExternalWrite: true}).Privileged() {
		t.Error("external.write privileged olmalı")
	}
	if (CapSet{"incident.read": true}).Privileged() {
		t.Error("incident.read privileged olmamalı")
	}
	if (CapSet{}).Privileged() {
		t.Error("boş küme privileged olmamalı")
	}
}
