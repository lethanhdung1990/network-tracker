package monitor

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"network-tracker/internal/config"
	"network-tracker/internal/winapi"
)

// TrackedConnection represents a fully correlated network socket event
type TrackedConnection struct {
	Timestamp   time.Time `json:"timestamp"`
	Event       string    `json:"event"`        // CONNECT, ESTAB, CLOSE, LISTEN, TIME_WAIT
	IsDelta     bool      `json:"is_delta"`     // True if this is a real-time event (CONNECT, CLOSE, new LISTEN)
	Protocol    string    `json:"protocol"`     // TCP, UDP
	PID         uint32    `json:"pid"`
	ProcessName string    `json:"process_name"`
	ProcessPath string    `json:"process_path"`
	LocalIP     string    `json:"local_ip"`
	LocalPort   int       `json:"local_port"`
	RemoteIP    string    `json:"remote_ip"`
	RemotePort  int       `json:"remote_port"`
	Domain      string    `json:"domain"`
	State       string    `json:"state"`
	UploadBps   uint64    `json:"upload_bps"`
	DownloadBps uint64    `json:"download_bps"`
}

// ConnectionPoller periodically scans and diffs kernel socket tables
type ConnectionPoller struct {
	cfg         *config.Config
	dns         *DNSResolver
	lifecycle   *LifecycleCache
	bandwidth   *BandwidthTracker
	mu          sync.Mutex
	prevTable   map[string]winapi.SocketInfo
	isFirstPoll bool
}

// NewConnectionPoller initializes the socket poller engine
func NewConnectionPoller(cfg *config.Config, dns *DNSResolver, lc *LifecycleCache, bw *BandwidthTracker) *ConnectionPoller {
	return &ConnectionPoller{
		cfg:         cfg,
		dns:         dns,
		lifecycle:   lc,
		bandwidth:   bw,
		prevTable:   make(map[string]winapi.SocketInfo),
		isFirstPoll: true,
	}
}

// UpdateConfig dynamically updates poller configuration at runtime (Hot-Reload)
func (cp *ConnectionPoller) UpdateConfig(cfg *config.Config) {
	if cfg == nil {
		return
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.cfg = cfg
}

func socketKey(s winapi.SocketInfo) string {
	return fmt.Sprintf("%s|%s:%d->%s:%d|%d", s.Protocol, s.LocalIP, s.LocalPort, s.RemoteIP, s.RemotePort, s.PID)
}

func isLoopback(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" || strings.HasPrefix(ip, "127.")
}

func isLAN(ip string) bool {
	return strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.16.")
}

// Poll captures current kernel sockets, diffs with previous snapshot, and returns events
func (cp *ConnectionPoller) Poll() ([]TrackedConnection, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	var allSockets []winapi.SocketInfo

	// 1. Scan TCP sockets
	if cp.cfg.Monitor.TrackTcp {
		tcpSockets, err := winapi.GetTcpTableIPv4()
		if err == nil {
			allSockets = append(allSockets, tcpSockets...)
		}
	}

	// 2. Scan UDP sockets
	if cp.cfg.Monitor.TrackUdp {
		udpSockets, err := winapi.GetUdpTableIPv4()
		if err == nil {
			allSockets = append(allSockets, udpSockets...)
		}
	}

	now := time.Now()
	currentTable := make(map[string]winapi.SocketInfo, len(allSockets))
	activePIDs := make(map[uint32]bool)
	results := make([]TrackedConnection, 0, len(allSockets))

	// 3. Process current socket snapshot
	for _, sock := range allSockets {
		if cp.cfg.Monitor.IgnoreLoopback && (isLoopback(sock.LocalIP) || isLoopback(sock.RemoteIP)) {
			continue
		}
		if cp.cfg.Monitor.IgnoreLan && isLAN(sock.RemoteIP) {
			continue
		}

		key := socketKey(sock)
		currentTable[key] = sock
		activePIDs[sock.PID] = true

		// Query executable metadata
		path, _ := winapi.GetProcessPath(sock.PID)
		name := winapi.GetProcessName(path)

		// If query fails (process exited), check Lifecycle Cache
		if path == "" || name == "Unknown" {
			if cached, found := cp.lifecycle.Get(sock.PID); found {
				name = cached.Name
				path = cached.Path
			}
		} else {
			// Record in Lifecycle Cache
			cp.lifecycle.Record(sock.PID, name, path)
		}

		// Resolve domain name
		domain := "-"
		if sock.RemoteIP != "0.0.0.0" && sock.RemoteIP != "" {
			domain = cp.dns.Resolve(sock.RemoteIP)
		}

		// Calculate I/O throughput
		downBps, upBps, _ := cp.bandwidth.UpdateAndGet(sock.PID)

		// Determine event: newly connected, newly listening, or ongoing
		event := "ESTAB"
		isDelta := false

		if cp.isFirstPoll {
			// On the first poll, establish baseline without generating false CONNECT events
			if sock.State == "LISTENING" {
				event = "LISTEN"
			}
			isDelta = false
		} else {
			if _, exists := cp.prevTable[key]; !exists {
				// New socket detected after baseline
				if sock.State == "LISTENING" {
					event = "LISTEN"
				} else {
					event = "CONNECT"
				}
				isDelta = true
			} else {
				// Ongoing socket
				if sock.State == "LISTENING" {
					event = "LISTEN"
				}
				isDelta = false
			}
		}

		results = append(results, TrackedConnection{
			Timestamp:   now,
			Event:       event,
			IsDelta:     isDelta,
			Protocol:    sock.Protocol,
			PID:         sock.PID,
			ProcessName: name,
			ProcessPath: path,
			LocalIP:     sock.LocalIP,
			LocalPort:   sock.LocalPort,
			RemoteIP:    sock.RemoteIP,
			RemotePort:  sock.RemotePort,
			Domain:      domain,
			State:       sock.State,
			UploadBps:   upBps,
			DownloadBps: downBps,
		})
	}

	// 4. Detect closed sockets (present in previous snapshot but absent now)
	if !cp.isFirstPoll {
		for prevKey, prevSock := range cp.prevTable {
			if _, exists := currentTable[prevKey]; !exists {
				path, _ := winapi.GetProcessPath(prevSock.PID)
				name := winapi.GetProcessName(path)
				if path == "" {
					if cached, found := cp.lifecycle.Get(prevSock.PID); found {
						name = cached.Name
						path = cached.Path
					}
				}

				domain := "-"
				if prevSock.RemoteIP != "0.0.0.0" {
					domain = cp.dns.Resolve(prevSock.RemoteIP)
				}

				results = append(results, TrackedConnection{
					Timestamp:   now,
					Event:       "CLOSE",
					IsDelta:     true,
					Protocol:    prevSock.Protocol,
					PID:         prevSock.PID,
					ProcessName: name,
					ProcessPath: path,
					LocalIP:     prevSock.LocalIP,
					LocalPort:   prevSock.LocalPort,
					RemoteIP:    prevSock.RemoteIP,
					RemotePort:  prevSock.RemotePort,
					Domain:      domain,
					State:       "CLOSED",
					UploadBps:   0,
					DownloadBps: 0,
				})
			}
		}
	}

	// Persist current snapshot for next polling round
	cp.prevTable = currentTable
	cp.isFirstPoll = false
	cp.bandwidth.Cleanup(activePIDs)

	return results, nil
}
