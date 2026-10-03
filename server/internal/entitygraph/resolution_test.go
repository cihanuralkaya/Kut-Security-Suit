package entitygraph

import (
	"testing"
	"time"
)

func TestResolveDevice(t *testing.T) {
	resolver := NewEntityResolver()
	tenant := "tenant1"
	
	ts1 := time.Now()
	
	// Test basic MAC resolution
	node1 := resolver.ResolveDevice(tenant, "192.168.1.10", "00:11:22:33:44:55", "host-a", ts1)
	if node1.Kind != Device {
		t.Errorf("Expected Device kind, got %s", node1.Kind)
	}
	
	// Same MAC, different IP should resolve to same node
	ts2 := ts1.Add(time.Minute)
	node2 := resolver.ResolveDevice(tenant, "192.168.1.20", "00:11:22:33:44:55", "host-a", ts2)
	if node1.ID != node2.ID {
		t.Errorf("Expected same device ID for same MAC. Got %s and %s", node1.ID, node2.ID)
	}
	
	// Hostname only should resolve to same if we already mapped hostname to MAC
	ts3 := ts2.Add(time.Minute)
	node3 := resolver.ResolveDevice(tenant, "", "", "host-a", ts3)
	if node1.ID != node3.ID {
		t.Errorf("Expected same device ID for mapped hostname. Got %s and %s", node1.ID, node3.ID)
	}
	
	// Different tenant should resolve to different node even with same MAC
	node4 := resolver.ResolveDevice("tenant2", "192.168.1.10", "00:11:22:33:44:55", "host-a", ts1)
	if node1.ID == node4.ID {
		t.Errorf("Expected different device ID for different tenant")
	}
}

func TestDeviceIPLeaseChanges(t *testing.T) {
	resolver := NewEntityResolver()
	tenant := "tenant1"
	
	ts1 := time.Now()
	// Device A gets IP
	nodeA := resolver.ResolveDevice(tenant, "10.0.0.5", "aa:aa:aa:aa:aa:aa", "device-a", ts1)
	
	// Process observes event with only IP, should map to Device A
	ts2 := ts1.Add(time.Second * 5)
	nodeObserv := resolver.ResolveDevice(tenant, "10.0.0.5", "", "", ts2)
	if nodeObserv.ID != nodeA.ID {
		t.Errorf("Expected event to map to Device A via IP lease")
	}
	
	// Device B gets same IP later
	ts3 := ts1.Add(time.Hour)
	nodeB := resolver.ResolveDevice(tenant, "10.0.0.5", "bb:bb:bb:bb:bb:bb", "device-b", ts3)
	if nodeB.ID == nodeA.ID {
		t.Errorf("Expected Device B to have different ID than Device A")
	}
	
	// Process observes event with IP now, should map to Device B
	ts4 := ts3.Add(time.Second * 5)
	nodeObserv2 := resolver.ResolveDevice(tenant, "10.0.0.5", "", "", ts4)
	if nodeObserv2.ID != nodeB.ID {
		t.Errorf("Expected event to map to Device B via updated IP lease")
	}
}

func TestResolveUser(t *testing.T) {
	resolver := NewEntityResolver()
	tenant := "tenant1"
	
	// Standard user@domain
	node1 := resolver.ResolveUser(tenant, "johndoe", "johndoe@corp.local", "corp.local")
	if node1.Kind != User {
		t.Errorf("Expected User kind, got %s", node1.Kind)
	}
	
	// DOMAIN\user format
	node2 := resolver.ResolveUser(tenant, "CORP.LOCAL\\johndoe", "", "")
	if node1.ID != node2.ID {
		t.Errorf("Expected same user ID for DOMAIN\\user format")
	}
	
	// user@domain as username
	node3 := resolver.ResolveUser(tenant, "johndoe@corp.local", "", "")
	if node1.ID != node3.ID {
		t.Errorf("Expected same user ID for user@domain username format")
	}
	
	// Different tenant
	node4 := resolver.ResolveUser("tenant2", "johndoe", "johndoe@corp.local", "corp.local")
	if node1.ID == node4.ID {
		t.Errorf("Expected different user ID for different tenant")
	}
}
