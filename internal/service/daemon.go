package service

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"network-tracker/internal/anomaly"
	"network-tracker/internal/config"
	"network-tracker/internal/logger"
	"network-tracker/internal/monitor"
	"network-tracker/internal/storage"
)

const PIDFileName = "logs/tracker.pid"

// WritePID writes the current process ID to the PID tracking file
func WritePID() error {
	_ = os.MkdirAll("logs", 0755)
	pid := os.Getpid()
	return os.WriteFile(PIDFileName, []byte(strconv.Itoa(pid)), 0644)
}

// ReadPID reads the process ID from the PID tracking file
func ReadPID() (int, error) {
	data, err := os.ReadFile(PIDFileName)
	if err != nil {
		return 0, err
	}
	pidStr := strings.TrimSpace(string(data))
	return strconv.Atoi(pidStr)
}

// RemovePID deletes the PID tracking file
func RemovePID() {
	_ = os.Remove(PIDFileName)
}

// IsRunning verifies whether the background process is currently active
func IsRunning() (bool, int) {
	pid, err := ReadPID()
	if err != nil || pid <= 0 {
		return false, 0
	}

	// On Windows, verify process liveness using OpenProcess
	handle, err := syscall.OpenProcess(0x1000, false, uint32(pid))
	if err != nil || handle == 0 {
		// Process is no longer alive; clean up stale PID file
		RemovePID()
		return false, 0
	}
	_ = syscall.CloseHandle(handle)
	return true, pid
}

// StopDaemon terminates the detached background process
func StopDaemon() error {
	running, pid := IsRunning()
	if !running {
		return fmt.Errorf("network-tracker is not currently running in background")
	}

	p, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("could not find process PID %d: %w", pid, err)
	}

	if err := p.Kill(); err != nil {
		return fmt.Errorf("failed to terminate process PID %d: %w", pid, err)
	}

	RemovePID()
	return nil
}

// RunService executes the main foreground/detached monitoring loop
func RunService(cfg *config.Config) error {
	if running, pid := IsRunning(); running {
		return fmt.Errorf("service is already running at PID %d", pid)
	}

	if err := WritePID(); err != nil {
		return fmt.Errorf("failed to write PID file: %w", err)
	}
	defer RemovePID()

	// Initialize core monitoring components
	dnsResolver := monitor.NewDNSResolver(cfg.DNS.Enabled, cfg.DNS.CacheSize, cfg.DNS.TimeoutMs)
	lifecycle := monitor.NewLifecycleCache(60 * time.Second)
	defer lifecycle.Stop()

	bandwidth := monitor.NewBandwidthTracker()
	poller := monitor.NewConnectionPoller(cfg, dnsResolver, lifecycle, bandwidth)
	detector := anomaly.NewAnomalyDetector(cfg)

	// Initialize logger
	logWriter, err := logger.NewLogger(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer logWriter.Close()

	// Initialize SQLite storage if enabled
	var store *storage.Storage
	if cfg.Database.Enabled {
		s, err := storage.NewStorage(cfg.Database.DbPath)
		if err == nil {
			store = s
			defer store.Close()
		}
	}

	// Listen for OS termination signals (Graceful Shutdown)
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, os.Interrupt, syscall.SIGTERM)

	interval := time.Duration(cfg.Monitor.ScanIntervalMs) * time.Millisecond
	if interval < 50*time.Millisecond {
		interval = 200 * time.Millisecond
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Setup Config Hot-Reload watcher
	cfgFilePath := config.ResolveConfigPath("config.json")
	var lastCfgMod time.Time
	if info, err := os.Stat(cfgFilePath); err == nil {
		lastCfgMod = info.ModTime()
	}
	tickCounter := 0

	fmt.Printf("[+] network-tracker running (PID: %d, scan interval: %v)...\n", os.Getpid(), interval)

	firstScan := true
	for {
		select {
		case <-stopCh:
			fmt.Println("\n[*] Shutting down network-tracker safely...")
			_ = logWriter.LogSystem("Daemon shutting down safely...")
			return nil

		case <-ticker.C:
			tickCounter++
			// Periodically check for config.json modifications (every ~1s)
			if tickCounter%5 == 0 {
				if modified, newMod := config.CheckModified(cfgFilePath, lastCfgMod); modified {
					lastCfgMod = newMod
					newCfg, err := config.LoadConfig(cfgFilePath)
					if err == nil && newCfg != nil {
						cfg = newCfg
						poller.UpdateConfig(newCfg)
						detector.UpdateConfig(newCfg)
						dnsResolver.UpdateConfig(newCfg.DNS.Enabled)
						_ = logWriter.UpdateConfig(newCfg)

						newInterval := time.Duration(newCfg.Monitor.ScanIntervalMs) * time.Millisecond
						if newInterval < 50*time.Millisecond {
							newInterval = 200 * time.Millisecond
						}
						if newInterval != interval {
							interval = newInterval
							ticker.Reset(interval)
						}

						_ = logWriter.LogSystem("All configuration parameters reloaded automatically from config.json (Hot-Reload)")
					} else if err != nil {
						_ = logWriter.LogSystem(fmt.Sprintf("Warning: Failed to reload config.json: %v (keeping active config)", err))
					}
				}
			}

			connections, err := poller.Poll()
			if err != nil {
				continue
			}

			if firstScan {
				firstScan = false
				_ = logWriter.LogSystem(fmt.Sprintf("Daemon started. Baseline established with %d active sockets. Tracking real-time changes...", len(connections)))
				continue
			}

			for _, conn := range connections {
				// 1. Record real-time changes only (CONNECT, CLOSE, new LISTEN)
				if conn.IsDelta {
					_ = logWriter.LogConnection(conn)
					if store != nil {
						_ = store.SaveConnection(conn)
					}
				}

				// 2. Evaluate deduplicated anomalies and write alerts
				newAlerts := detector.CheckNewAlerts(conn)
				for _, alt := range newAlerts {
					_ = logWriter.LogAlert(alt)
					if store != nil {
						_ = store.SaveAlert(alt)
					}
				}
			}
		}
	}
}

// GetExecutablePath returns the normalized absolute path of the permanent binary.
// If executed via 'go run', it resolves the path using config.json (service.executable_path / candidate_paths)
// rather than registering an ephemeral AppData/Local/Temp binary.
func GetExecutablePath(cfg *config.Config) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		exe = "network-tracker.exe"
	}

	lower := strings.ToLower(exe)
	isTempDevMode := strings.Contains(lower, "go-build") || (strings.Contains(lower, "temp") && !strings.Contains(lower, "dist"))

	// If not running in ephemeral dev mode, use current binary location
	if !isTempDevMode {
		return filepath.Abs(exe)
	}

	// 1. Check primary executable_path configured in config.json
	if cfg != nil && cfg.Service.ExecutablePath != "" {
		searchPaths := []string{
			cfg.Service.ExecutablePath,
			"../" + cfg.Service.ExecutablePath,
			"../../" + cfg.Service.ExecutablePath,
		}
		for _, sp := range searchPaths {
			if abs, err := filepath.Abs(sp); err == nil {
				if _, statErr := os.Stat(abs); statErr == nil {
					return abs, nil
				}
			}
		}
	}

	// 2. Check candidate_paths configured in config.json
	var candidates []string
	if cfg != nil && len(cfg.Service.CandidatePaths) > 0 {
		candidates = append(candidates, cfg.Service.CandidatePaths...)
	} else {
		candidates = []string{
			"dist/network-tracker.exe",
			"network-tracker.exe",
		}
	}

	for _, c := range candidates {
		searchPaths := []string{
			c,
			"../" + c,
			"../../" + c,
		}
		for _, sp := range searchPaths {
			if abs, err := filepath.Abs(sp); err == nil {
				if _, statErr := os.Stat(abs); statErr == nil {
					return abs, nil
				}
			}
		}
	}

	return "", fmt.Errorf("cannot install service using temporary 'go run' binary: permanent binary not found in candidate paths. Please configure 'service.candidate_paths' in config.json or run 'build.bat'")
}
