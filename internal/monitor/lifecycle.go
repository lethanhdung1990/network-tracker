package monitor

import (
	"sync"
	"time"
)

// ProcessInfo holds process identification metadata
type ProcessInfo struct {
	PID      uint32
	Name     string
	Path     string
	LastSeen time.Time
}

// LifecycleCache retains process metadata for 60 seconds to catch ephemeral processes (50ms - 100ms)
type LifecycleCache struct {
	mu     sync.RWMutex
	cache  map[uint32]ProcessInfo
	ttl    time.Duration
	stopCh chan struct{}
}

// NewLifecycleCache initializes the process lifecycle cache
func NewLifecycleCache(ttl time.Duration) *LifecycleCache {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	lc := &LifecycleCache{
		cache:  make(map[uint32]ProcessInfo),
		ttl:    ttl,
		stopCh: make(chan struct{}),
	}
	go lc.startCleanupRoutine()
	return lc
}

// Record saves PID and binary image path into the lifecycle cache
func (lc *LifecycleCache) Record(pid uint32, name, path string) {
	if pid == 0 || name == "" {
		return
	}
	lc.mu.Lock()
	defer lc.mu.Unlock()

	lc.cache[pid] = ProcessInfo{
		PID:      pid,
		Name:     name,
		Path:     path,
		LastSeen: time.Now(),
	}
}

// Get queries saved process metadata (even if the process has already terminated)
func (lc *LifecycleCache) Get(pid uint32) (ProcessInfo, bool) {
	lc.mu.RLock()
	defer lc.mu.RUnlock()

	info, found := lc.cache[pid]
	return info, found
}

// startCleanupRoutine periodically purges records exceeding TTL
func (lc *LifecycleCache) startCleanupRoutine() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			lc.mu.Lock()
			now := time.Now()
			for pid, info := range lc.cache {
				if now.Sub(info.LastSeen) > lc.ttl {
					delete(lc.cache, pid)
				}
			}
			lc.mu.Unlock()
		case <-lc.stopCh:
			return
		}
	}
}

// Stop gracefully shuts down the background purge goroutine
func (lc *LifecycleCache) Stop() {
	close(lc.stopCh)
}
