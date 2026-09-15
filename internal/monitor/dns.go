package monitor

import (
	"net"
	"strings"
	"sync"
	"time"
)

type dnsEntry struct {
	domain    string
	expiresAt time.Time
}

// DNSResolver manages IP-to-domain resolution with asynchronous cache updates
type DNSResolver struct {
	mu      sync.RWMutex
	cache   map[string]dnsEntry
	ttl     time.Duration
	enabled bool
}

// NewDNSResolver initializes the DNS resolver cache
func NewDNSResolver(enabled bool, cacheSize int, timeoutMs int) *DNSResolver {
	r := &DNSResolver{
		cache:   make(map[string]dnsEntry, cacheSize),
		ttl:     30 * time.Minute, // Retain domain entries in cache for 30 minutes
		enabled: enabled,
	}

	// Prepopulate static entries
	r.cache["127.0.0.1"] = dnsEntry{domain: "localhost", expiresAt: time.Now().Add(24 * time.Hour)}
	r.cache["::1"] = dnsEntry{domain: "localhost", expiresAt: time.Now().Add(24 * time.Hour)}
	r.cache["0.0.0.0"] = dnsEntry{domain: "-", expiresAt: time.Now().Add(24 * time.Hour)}

	return r
}

// UpdateConfig dynamically updates DNS resolver settings at runtime (Hot-Reload)
func (r *DNSResolver) UpdateConfig(enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = enabled
}

// Resolve returns the cached domain name for an IP (non-blocking, never stalls polling loop)
func (r *DNSResolver) Resolve(ip string) string {
	if !r.enabled || ip == "" || ip == "0.0.0.0" {
		return "-"
	}

	r.mu.RLock()
	entry, found := r.cache[ip]
	r.mu.RUnlock()

	if found && time.Now().Before(entry.expiresAt) {
		return entry.domain
	}

	// If missing or expired, dispatch asynchronous background lookup
	go r.asyncLookup(ip)

	if found {
		return entry.domain // Return stale cached value temporarily
	}
	return "-"
}

// asyncLookup performs reverse DNS resolution without blocking the caller
func (r *DNSResolver) asyncLookup(ip string) {
	// Skip private/internal ranges without reverse DNS
	if strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.") {
		r.Set(ip, "LAN", 1*time.Hour)
		return
	}

	names, err := net.LookupAddr(ip)
	domain := "-"
	if err == nil && len(names) > 0 {
		domain = strings.TrimSuffix(names[0], ".")
	}

	r.Set(ip, domain, r.ttl)
}

// Set saves a resolved domain entry into the cache
func (r *DNSResolver) Set(ip, domain string, ttl time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[ip] = dnsEntry{
		domain:    domain,
		expiresAt: time.Now().Add(ttl),
	}
}
