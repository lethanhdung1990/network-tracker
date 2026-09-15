package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Config represents the master configuration structure for network-tracker
type Config struct {
	Monitor  MonitorConfig  `json:"monitor"`
	DNS      DNSConfig      `json:"dns"`
	Alerts   AlertsConfig   `json:"alerts"`
	Logging  LoggingConfig  `json:"logging"`
	Database DatabaseConfig `json:"database"`
	UI       UIConfig       `json:"ui"`
	Service  ServiceConfig  `json:"service"`
}

type MonitorConfig struct {
	ScanIntervalMs   int      `json:"scan_interval_ms"`
	TrackTcp         bool     `json:"track_tcp"`
	TrackUdp         bool     `json:"track_udp"`
	IgnoreLoopback   bool     `json:"ignore_loopback"`
	IgnoreLan        bool     `json:"ignore_lan"`
	TrustedProcesses []string `json:"trusted_processes"`
}

type DNSConfig struct {
	Enabled   bool `json:"enabled"`
	CacheSize int  `json:"cache_size"`
	TimeoutMs int  `json:"timeout_ms"`
}

type AlertsConfig struct {
	BurstThreshold            int      `json:"burst_threshold"`
	BurstWindowSeconds        int      `json:"burst_window_seconds"`
	BandwidthSpikeBytesPerSec int      `json:"bandwidth_spike_bytes_per_sec"`
	SuspiciousPaths           []string `json:"suspicious_paths"`
	AlertUnusualPorts         bool     `json:"alert_unusual_ports"`
	StandardPorts             []int    `json:"standard_ports"`
	BlacklistDomains          []string `json:"blacklist_domains"`
	BlacklistIps              []string `json:"blacklist_ips"`
}

type LoggingConfig struct {
	LogDir          string `json:"log_dir"`
	DailyFolder     bool   `json:"daily_folder"`
	MaxFileSizeMb   int    `json:"max_file_size_mb"`
	BackupCount     int    `json:"backup_count"`
	EnableTextLog   bool   `json:"enable_text_log"`
	EnableJsonl     bool   `json:"enable_jsonl"`
	FormatTemplate  string `json:"format_template"`
	TimestampFormat string `json:"timestamp_format"`
}

type DatabaseConfig struct {
	Enabled       bool   `json:"enabled"`
	DbPath        string `json:"db_path"`
	RetentionDays int    `json:"retention_days"`
}

type UIConfig struct {
	RowsPerPage int `json:"rows_per_page"`
}

type ServiceConfig struct {
	Name           string   `json:"name"`
	DisplayName    string   `json:"display_name"`
	Description    string   `json:"description"`
	ExecutablePath string   `json:"executable_path"`
	CandidatePaths []string `json:"candidate_paths"`
}

// ResolveConfigPath locates the active configuration file across candidate directories
func ResolveConfigPath(cfgPath string) string {
	candidatePaths := []string{
		cfgPath,
		"../" + cfgPath,
		"../../" + cfgPath,
	}

	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		candidatePaths = append(candidatePaths,
			filepath.Join(exeDir, cfgPath),
			filepath.Join(filepath.Dir(exeDir), cfgPath),
		)
	}

	for _, p := range candidatePaths {
		if _, err := os.Stat(p); err == nil {
			if abs, err := filepath.Abs(p); err == nil {
				return abs
			}
			return p
		}
	}
	return cfgPath
}

// CheckModified checks if the file has been modified since lastMod timestamp
func CheckModified(path string, lastMod time.Time) (bool, time.Time) {
	info, err := os.Stat(path)
	if err != nil {
		return false, lastMod
	}
	currentMod := info.ModTime()
	if currentMod.After(lastMod) {
		return true, currentMod
	}
	return false, lastMod
}

// LoadConfig loads and parses the configuration file with candidate fallback paths
func LoadConfig(cfgPath string) (*Config, error) {
	resolved := ResolveConfigPath(cfgPath)
	data, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("read file error %s: %w", resolved, err)
	}

	// Align working directory with config directory if needed
	dir := filepath.Dir(resolved)
	if dir != "" && dir != "." {
		_ = os.Chdir(dir)
	}

	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("parse config json error %s: %w", cfgPath, err)
	}

	// Apply defaults
	if config.UI.RowsPerPage <= 0 {
		config.UI.RowsPerPage = 8
	}
	if config.Service.Name == "" {
		config.Service.Name = "NetworkTracker"
	}
	if config.Service.DisplayName == "" {
		config.Service.DisplayName = "Network Tracker Monitoring Service"
	}
	if config.Service.Description == "" {
		config.Service.Description = "24/7 background network connection monitor, ephemeral process tracker, and anomaly detection system."
	}
	if config.Service.ExecutablePath == "" {
		config.Service.ExecutablePath = "dist/network-tracker.exe"
	}
	if len(config.Service.CandidatePaths) == 0 {
		config.Service.CandidatePaths = []string{
			"dist/network-tracker.exe",
			"network-tracker.exe",
		}
	}

	return &config, nil
}
