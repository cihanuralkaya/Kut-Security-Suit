package entitygraph

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)



// lease record for temporal mappings
type lease struct {
	ip         string
	mac        string
	hostname   string
	deviceNode Node
	updatedAt  time.Time
}

// EntityResolver resolves transient indicators to canonical entities
type EntityResolver struct {
	mu sync.RWMutex
	// tenantID -> mapping tables
	
	// Mac to canonical device ID mapping
	macToDevice map[string]map[string]Node
	// Hostname to canonical device ID mapping
	hostToDevice map[string]map[string]Node
	
	// IP to latest lease mapping
	ipLeases map[string]map[string]*lease
	
	// User normalization cache
	userToNode map[string]map[string]Node
}

// NewEntityResolver creates a new Real-Time Entity Resolution Engine
func NewEntityResolver() *EntityResolver {
	return &EntityResolver{
		macToDevice:  make(map[string]map[string]Node),
		hostToDevice: make(map[string]map[string]Node),
		ipLeases:     make(map[string]map[string]*lease),
		userToNode:   make(map[string]map[string]Node),
	}
}

// ResolveDevice maps transient device indicators (IP, MAC, hostname) to a canonical Device node
func (r *EntityResolver) ResolveDevice(tenant string, ip string, mac string, hostname string, ts time.Time) Node {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.initTenant(tenant)

	// Clean up inputs
	ip = strings.TrimSpace(ip)
	mac = strings.ToLower(strings.TrimSpace(mac))
	hostname = strings.ToLower(strings.TrimSpace(hostname))

	var canonicalNode Node
	found := false

	// Try to resolve by MAC first (strongest indicator)
	if mac != "" {
		if n, ok := r.macToDevice[tenant][mac]; ok {
			canonicalNode = n
			found = true
		}
	}

	// Try hostname if MAC didn't resolve
	if !found && hostname != "" {
		if n, ok := r.hostToDevice[tenant][hostname]; ok {
			canonicalNode = n
			found = true
		}
	}

	// Try IP lease if still not found and no specific hardware or hostname was provided
	if !found && mac == "" && hostname == "" && ip != "" {
		if l, ok := r.ipLeases[tenant][ip]; ok {
			if l.updatedAt.Before(ts) || l.updatedAt.Equal(ts) {
				canonicalNode = l.deviceNode
				found = true
			}
		}
	}

	// If no canonical node found, create a new one
	if !found {
		// Generate deterministic ID based on strongest indicator
		base := mac
		if base == "" {
			base = hostname
		}
		if base == "" {
			base = ip
		}
		if base == "" {
			base = fmt.Sprintf("unknown-%d", ts.UnixNano())
		}
		
		canonicalID := generateID(tenant, "device", base)
		canonicalNode = Node{
			Kind:   Device,
			ID:     canonicalID,
			Tenant: tenant,
		}
	}

	// Update mappings with the canonical node
	if mac != "" {
		r.macToDevice[tenant][mac] = canonicalNode
	}
	if hostname != "" {
		r.hostToDevice[tenant][hostname] = canonicalNode
	}
	
	// Update IP lease
	if ip != "" {
		currentLease, ok := r.ipLeases[tenant][ip]
		if !ok || currentLease.updatedAt.Before(ts) || currentLease.deviceNode.ID == canonicalNode.ID {
			r.ipLeases[tenant][ip] = &lease{
				ip:         ip,
				mac:        mac,
				hostname:   hostname,
				deviceNode: canonicalNode,
				updatedAt:  ts,
			}
		}
	}

	return canonicalNode
}

// ResolveUser normalizes user identifiers into a canonical User node
func (r *EntityResolver) ResolveUser(tenant string, username string, email string, domain string) Node {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.initTenant(tenant)

	// Normalize inputs
	username = strings.ToLower(strings.TrimSpace(username))
	email = strings.ToLower(strings.TrimSpace(email))
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Extract domain and user from formats like DOMAIN\user or user@domain
	if strings.Contains(username, "\\") {
		parts := strings.SplitN(username, "\\", 2)
		domain = parts[0]
		username = parts[1]
	} else if strings.Contains(username, "@") {
		parts := strings.SplitN(username, "@", 2)
		username = parts[0]
		domain = parts[1]
	}

	if email != "" && username == "" {
		parts := strings.SplitN(email, "@", 2)
		if len(parts) == 2 {
			username = parts[0]
			if domain == "" {
				domain = parts[1]
			}
		}
	}

	// Determine canonical identifier
	var canonicalID string
	if email != "" {
		canonicalID = email
	} else if domain != "" && username != "" {
		canonicalID = fmt.Sprintf("%s@%s", username, domain)
	} else {
		canonicalID = username
	}

	if n, ok := r.userToNode[tenant][canonicalID]; ok {
		return n
	}

	nodeID := generateID(tenant, "user", canonicalID)
	node := Node{
		Kind:   User,
		ID:     nodeID,
		Tenant: tenant,
	}

	r.userToNode[tenant][canonicalID] = node

	// Map other known variants
	if email != "" {
		r.userToNode[tenant][email] = node
	}
	if domain != "" && username != "" {
		variant1 := fmt.Sprintf("%s\\%s", domain, username)
		variant2 := fmt.Sprintf("%s@%s", username, domain)
		r.userToNode[tenant][variant1] = node
		r.userToNode[tenant][variant2] = node
	}
	if username != "" && domain == "" && email == "" {
		r.userToNode[tenant][username] = node
	}

	return node
}

func (r *EntityResolver) initTenant(tenant string) {
	if _, ok := r.macToDevice[tenant]; !ok {
		r.macToDevice[tenant] = make(map[string]Node)
		r.hostToDevice[tenant] = make(map[string]Node)
		r.ipLeases[tenant] = make(map[string]*lease)
		r.userToNode[tenant] = make(map[string]Node)
	}
}

func generateID(tenant, kind, indicator string) string {
	h := sha256.New()
	h.Write([]byte(tenant))
	h.Write([]byte(kind))
	h.Write([]byte(indicator))
	return hex.EncodeToString(h.Sum(nil))[:16]
}
