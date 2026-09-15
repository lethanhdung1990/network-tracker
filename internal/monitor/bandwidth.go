package monitor

import (
	"sync"
	"time"

	"network-tracker/internal/winapi"
)

type ioRecord struct {
	counters  winapi.IO_COUNTERS
	updatedAt time.Time
	readBps   uint64
	writeBps  uint64
}

// BandwidthTracker calculates per-process I/O throughput in bytes per second
type BandwidthTracker struct {
	mu      sync.RWMutex
	records map[uint32]ioRecord
}

// NewBandwidthTracker initializes the per-process bandwidth tracking engine
func NewBandwidthTracker() *BandwidthTracker {
	return &BandwidthTracker{
		records: make(map[uint32]ioRecord),
	}
}

// UpdateAndGet computes and returns the transfer rate in bytes per second
func (bt *BandwidthTracker) UpdateAndGet(pid uint32) (readBps uint64, writeBps uint64, totalBps uint64) {
	if pid == 0 || pid == 4 {
		return 0, 0, 0
	}

	counters, err := winapi.GetProcessIo(pid)
	if err != nil {
		return 0, 0, 0
	}

	now := time.Now()

	bt.mu.Lock()
	defer bt.mu.Unlock()

	prev, exists := bt.records[pid]
	if !exists {
		bt.records[pid] = ioRecord{
			counters:  counters,
			updatedAt: now,
			readBps:   0,
			writeBps:  0,
		}
		return 0, 0, 0
	}

	deltaSec := now.Sub(prev.updatedAt).Seconds()
	if deltaSec <= 0.1 {
		// Interval too short (<100ms), return previous calculated rates
		return prev.readBps, prev.writeBps, prev.readBps + prev.writeBps
	}

	var rBps, wBps uint64
	if counters.ReadTransferCount >= prev.counters.ReadTransferCount {
		rBps = uint64(float64(counters.ReadTransferCount-prev.counters.ReadTransferCount) / deltaSec)
	}
	if counters.WriteTransferCount >= prev.counters.WriteTransferCount {
		wBps = uint64(float64(counters.WriteTransferCount-prev.counters.WriteTransferCount) / deltaSec)
	}

	bt.records[pid] = ioRecord{
		counters:  counters,
		updatedAt: now,
		readBps:   rBps,
		writeBps:  wBps,
	}

	return rBps, wBps, rBps + wBps
}

// Cleanup removes terminated process IDs from tracking cache
func (bt *BandwidthTracker) Cleanup(activePIDs map[uint32]bool) {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	for pid := range bt.records {
		if !activePIDs[pid] {
			delete(bt.records, pid)
		}
	}
}
