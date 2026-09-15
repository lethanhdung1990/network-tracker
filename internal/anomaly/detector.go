package anomaly

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"network-tracker/internal/config"
	"network-tracker/internal/monitor"
)

// Alert defines the security and traffic anomaly notification structure
type Alert struct {
	Timestamp   time.Time      `json:"timestamp"`
	Level       string         `json:"level"` // HIGH, MEDIUM, LOW
	Type        string         `json:"type"`  // SUSPICIOUS_PATH, HIGH_BURST, etc.
	Message     string         `json:"message"`
	ProcessName string         `json:"process_name"`
	PID         uint32         `json:"pid"`
	Endpoint    string         `json:"endpoint"`
	Domain      string         `json:"domain"`
	Details     map[string]any `json:"details"`
}

// AnomalyDetector evaluates security rules against each active socket
type AnomalyDetector struct {
	cfg           *config.Config
	standardPorts map[int]bool
	blacklistIps  map[string]bool
	blacklistDom  map[string]bool
	mu            sync.Mutex
	burstHistory  map[uint32][]time.Time // Sliding window timestamps for burst detection
	activeAlerts  map[string]time.Time   // Deduplication cache: connAlertKey -> lastAlertTime
}

// NewAnomalyDetector constructs the anomaly detection engine
func NewAnomalyDetector(cfg *config.Config) *AnomalyDetector {
	stdPorts := make(map[int]bool)
	for _, p := range cfg.Alerts.StandardPorts {
		stdPorts[p] = true
	}

	blIps := make(map[string]bool)
	for _, ip := range cfg.Alerts.BlacklistIps {
		blIps[ip] = true
	}

	blDom := make(map[string]bool)
	for _, d := range cfg.Alerts.BlacklistDomains {
		blDom[strings.ToLower(d)] = true
	}

	return &AnomalyDetector{
		cfg:           cfg,
		standardPorts: stdPorts,
		blacklistIps:  blIps,
		blacklistDom:  blDom,
		burstHistory:  make(map[uint32][]time.Time),
		activeAlerts:  make(map[string]time.Time),
	}
}

// UpdateConfig dynamically updates anomaly detector rules at runtime (Hot-Reload)
func (ad *AnomalyDetector) UpdateConfig(cfg *config.Config) {
	if cfg == nil {
		return
	}

	stdPorts := make(map[int]bool)
	for _, p := range cfg.Alerts.StandardPorts {
		stdPorts[p] = true
	}

	blIps := make(map[string]bool)
	for _, ip := range cfg.Alerts.BlacklistIps {
		blIps[ip] = true
	}

	blDom := make(map[string]bool)
	for _, d := range cfg.Alerts.BlacklistDomains {
		blDom[strings.ToLower(d)] = true
	}

	ad.mu.Lock()
	defer ad.mu.Unlock()
	ad.cfg = cfg
	ad.standardPorts = stdPorts
	ad.blacklistIps = blIps
	ad.blacklistDom = blDom
}

// Check evaluates a connection and returns any triggered security alerts
func (ad *AnomalyDetector) Check(conn monitor.TrackedConnection) []Alert {
	var alerts []Alert

	// 1. Ignore trusted processes
	for _, trusted := range ad.cfg.Monitor.TrustedProcesses {
		if strings.EqualFold(conn.ProcessName, trusted) {
			return nil
		}
	}

	// 2. Detect suspicious executable paths (SUSPICIOUS_PATH)
	if conn.ProcessPath != "" {
		lowerPath := strings.ToLower(conn.ProcessPath)
		for _, sp := range ad.cfg.Alerts.SuspiciousPaths {
			if strings.Contains(lowerPath, strings.ToLower(sp)) {
				alerts = append(alerts, Alert{
					Timestamp:   conn.Timestamp,
					Level:       "HIGH",
					Type:        "SUSPICIOUS_PATH",
					Message:     fmt.Sprintf("Process executing from suspicious location: %s", conn.ProcessPath),
					ProcessName: conn.ProcessName,
					PID:         conn.PID,
					Endpoint:    fmt.Sprintf("%s:%d", conn.RemoteIP, conn.RemotePort),
					Domain:      conn.Domain,
					Details:     map[string]any{"matched_rule": sp},
				})
				break
			}
		}
	}

	// 3. Detect blacklisted remote IP (BLACKLIST_IP)
	if ad.blacklistIps[conn.RemoteIP] {
		alerts = append(alerts, Alert{
			Timestamp:   conn.Timestamp,
			Level:       "HIGH",
			Type:        "BLACKLIST_IP",
			Message:     fmt.Sprintf("Connection established to blacklisted IP: %s", conn.RemoteIP),
			ProcessName: conn.ProcessName,
			PID:         conn.PID,
			Endpoint:    fmt.Sprintf("%s:%d", conn.RemoteIP, conn.RemotePort),
			Domain:      conn.Domain,
			Details:     map[string]any{"ip": conn.RemoteIP},
		})
	}

	// 4. Detect blacklisted remote domain (BLACKLIST_DOMAIN)
	if conn.Domain != "-" && conn.Domain != "" && ad.blacklistDom[strings.ToLower(conn.Domain)] {
		alerts = append(alerts, Alert{
			Timestamp:   conn.Timestamp,
			Level:       "HIGH",
			Type:        "BLACKLIST_DOMAIN",
			Message:     fmt.Sprintf("Connection established to blacklisted domain: %s", conn.Domain),
			ProcessName: conn.ProcessName,
			PID:         conn.PID,
			Endpoint:    fmt.Sprintf("%s:%d", conn.RemoteIP, conn.RemotePort),
			Domain:      conn.Domain,
			Details:     map[string]any{"domain": conn.Domain},
		})
	}

	// 5. Detect unusual destination port (UNUSUAL_PORT)
	if ad.cfg.Alerts.AlertUnusualPorts && conn.RemotePort > 0 {
		if !ad.standardPorts[conn.RemotePort] {
			alerts = append(alerts, Alert{
				Timestamp:   conn.Timestamp,
				Level:       "MEDIUM",
				Type:        "UNUSUAL_PORT",
				Message:     fmt.Sprintf("Outbound connection to unusual port %d (outside standard whitelist)", conn.RemotePort),
				ProcessName: conn.ProcessName,
				PID:         conn.PID,
				Endpoint:    fmt.Sprintf("%s:%d", conn.RemoteIP, conn.RemotePort),
				Domain:      conn.Domain,
				Details:     map[string]any{"port": conn.RemotePort},
			})
		}
	}

	// 6. Detect rapid connection burst (HIGH_BURST) on CONNECT events
	if conn.Event == "CONNECT" {
		burstAlert := ad.checkBurst(conn)
		if burstAlert != nil {
			alerts = append(alerts, *burstAlert)
		}
	}

	// 7. Detect high bandwidth spike (BANDWIDTH_SPIKE)
	totalBps := conn.UploadBps + conn.DownloadBps
	if ad.cfg.Alerts.BandwidthSpikeBytesPerSec > 0 && totalBps > uint64(ad.cfg.Alerts.BandwidthSpikeBytesPerSec) {
		alerts = append(alerts, Alert{
			Timestamp:   conn.Timestamp,
			Level:       "HIGH",
			Type:        "BANDWIDTH_SPIKE",
			Message:     fmt.Sprintf("Process consuming excessive network bandwidth: %.2f MB/s", float64(totalBps)/1048576.0),
			ProcessName: conn.ProcessName,
			PID:         conn.PID,
			Endpoint:    fmt.Sprintf("%s:%d", conn.RemoteIP, conn.RemotePort),
			Domain:      conn.Domain,
			Details: map[string]any{
				"total_bytes_sec": totalBps,
				"upload_bps":      conn.UploadBps,
				"download_bps":    conn.DownloadBps,
			},
		})
	}

	return alerts
}

// checkBurst uses a sliding window algorithm to detect connection bursts
func (ad *AnomalyDetector) checkBurst(conn monitor.TrackedConnection) *Alert {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	now := conn.Timestamp
	windowStart := now.Add(-time.Duration(ad.cfg.Alerts.BurstWindowSeconds) * time.Second)

	var validTimes []time.Time
	for _, t := range ad.burstHistory[conn.PID] {
		if t.After(windowStart) {
			validTimes = append(validTimes, t)
		}
	}

	validTimes = append(validTimes, now)
	ad.burstHistory[conn.PID] = validTimes

	if len(validTimes) >= ad.cfg.Alerts.BurstThreshold {
		return &Alert{
			Timestamp:   now,
			Level:       "HIGH",
			Type:        "HIGH_BURST",
			Message:     fmt.Sprintf("Rapid connection burst: %d connections opened in %ds (Threshold: %d)", len(validTimes), ad.cfg.Alerts.BurstWindowSeconds, ad.cfg.Alerts.BurstThreshold),
			ProcessName: conn.ProcessName,
			PID:         conn.PID,
			Endpoint:    fmt.Sprintf("%s:%d", conn.RemoteIP, conn.RemotePort),
			Domain:      conn.Domain,
			Details: map[string]any{
				"connections_in_window": len(validTimes),
				"window_sec":            ad.cfg.Alerts.BurstWindowSeconds,
			},
		}
	}

	return nil
}

// CheckNewAlerts evaluates rules for background logging and returns ONLY newly triggered alerts.
// It deduplicates alerts so ongoing sockets do not repeatedly log the same alert on every scan.
func (ad *AnomalyDetector) CheckNewAlerts(conn monitor.TrackedConnection) []Alert {
	connPrefix := fmt.Sprintf("%s|%d|%s:%d->%s:%d|", conn.Protocol, conn.PID, conn.LocalIP, conn.LocalPort, conn.RemoteIP, conn.RemotePort)

	// If the connection has closed, purge any active alerts recorded for this socket
	if conn.Event == "CLOSE" {
		ad.mu.Lock()
		for k := range ad.activeAlerts {
			if strings.HasPrefix(k, connPrefix) {
				delete(ad.activeAlerts, k)
			}
		}
		ad.mu.Unlock()
		return nil
	}

	// For ongoing connections (!IsDelta), only dynamic checks (bandwidth spikes) apply
	if !conn.IsDelta {
		totalBps := conn.UploadBps + conn.DownloadBps
		if ad.cfg.Alerts.BandwidthSpikeBytesPerSec <= 0 || totalBps <= uint64(ad.cfg.Alerts.BandwidthSpikeBytesPerSec) {
			return nil
		}
	}

	rawAlerts := ad.Check(conn)
	if len(rawAlerts) == 0 {
		return nil
	}

	ad.mu.Lock()
	defer ad.mu.Unlock()

	now := time.Now()
	// Periodic cleanup of stale alerts (> 2 hours old) to prevent memory leak
	if len(ad.activeAlerts) > 1000 {
		for k, t := range ad.activeAlerts {
			if now.Sub(t) > 2*time.Hour {
				delete(ad.activeAlerts, k)
			}
		}
	}

	var newAlerts []Alert
	for _, alt := range rawAlerts {
		alertKey := connPrefix + alt.Type

		lastAlerted, exists := ad.activeAlerts[alertKey]
		if !exists {
			// First time this alert triggered for this connection
			ad.activeAlerts[alertKey] = now
			newAlerts = append(newAlerts, alt)
		} else if alt.Type == "BANDWIDTH_SPIKE" {
			// Dynamic bandwidth spikes can re-alert after cooldown (e.g. 60 seconds)
			if now.Sub(lastAlerted) >= 60*time.Second {
				ad.activeAlerts[alertKey] = now
				newAlerts = append(newAlerts, alt)
			}
		}
	}

	return newAlerts
}
