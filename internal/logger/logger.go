package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"network-tracker/internal/anomaly"
	"network-tracker/internal/config"
	"network-tracker/internal/monitor"
)

// MultiChannelLogger manages multi-channel logging, daily directory partitioning, and 100MB rotation
type MultiChannelLogger struct {
	cfg        *config.Config
	mu         sync.Mutex
	currentDay string
	dayDir     string

	networkFile *os.File
	alertsFile  *os.File
	jsonlFile   *os.File

	networkSize int64
	alertsSize  int64
	jsonlSize   int64

	maxSizeBytes int64
}

// NewLogger initializes the logging subsystem
func NewLogger(cfg *config.Config) (*MultiChannelLogger, error) {
	maxBytes := int64(cfg.Logging.MaxFileSizeMb) * 1024 * 1024
	if maxBytes <= 0 {
		maxBytes = 100 * 1024 * 1024 // 100MB default
	}

	l := &MultiChannelLogger{
		cfg:          cfg,
		maxSizeBytes: maxBytes,
	}

	if err := l.rotateDayIfNeeded(time.Now()); err != nil {
		return nil, err
	}

	return l, nil
}

// UpdateConfig dynamically updates logging configuration at runtime (Hot-Reload)
func (l *MultiChannelLogger) UpdateConfig(cfg *config.Config) error {
	if cfg == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	l.cfg = cfg
	maxBytes := int64(cfg.Logging.MaxFileSizeMb) * 1024 * 1024
	if maxBytes <= 0 {
		maxBytes = 100 * 1024 * 1024
	}
	l.maxSizeBytes = maxBytes

	l.closeFiles()
	return l.rotateDayIfNeeded(time.Now())
}

// rotateDayIfNeeded rotates logs when a new calendar day begins (00:00:00)
func (l *MultiChannelLogger) rotateDayIfNeeded(t time.Time) error {
	dayStr := t.Format("2006-01-02")
	if l.currentDay == dayStr && l.networkFile != nil {
		return nil
	}

	l.closeFiles()

	baseDir := l.cfg.Logging.LogDir
	if baseDir == "" {
		baseDir = "logs"
	}

	dayDir := baseDir
	if l.cfg.Logging.DailyFolder {
		dayDir = filepath.Join(baseDir, dayStr)
	}

	if err := os.MkdirAll(dayDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory %s: %w", dayDir, err)
	}

	l.currentDay = dayStr
	l.dayDir = dayDir

	// Open logs for the new day
	if l.cfg.Logging.EnableTextLog {
		f, size, err := openLogFileWithRotation(dayDir, "network.log", l.maxSizeBytes)
		if err != nil {
			return err
		}
		l.networkFile = f
		l.networkSize = size

		af, aSize, err := openLogFileWithRotation(dayDir, "alerts.log", l.maxSizeBytes)
		if err != nil {
			return err
		}
		l.alertsFile = af
		l.alertsSize = aSize
	}

	if l.cfg.Logging.EnableJsonl {
		jf, jSize, err := openLogFileWithRotation(dayDir, "connections.jsonl", l.maxSizeBytes)
		if err != nil {
			return err
		}
		l.jsonlFile = jf
		l.jsonlSize = jSize
	}

	return nil
}

// openLogFileWithRotation opens a log file and handles size-based rotation (max 100MB)
func openLogFileWithRotation(dir, baseName string, maxSize int64) (*os.File, int64, error) {
	fullPath := filepath.Join(dir, baseName)
	info, err := os.Stat(fullPath)
	if err == nil {
		if info.Size() >= maxSize {
			// Rotate to numbered suffix (e.g. network_1.log)
			for i := 1; i <= 100; i++ {
				ext := filepath.Ext(baseName)
				nameWithoutExt := baseName[:len(baseName)-len(ext)]
				rotatedName := fmt.Sprintf("%s_%d%s", nameWithoutExt, i, ext)
				rotatedPath := filepath.Join(dir, rotatedName)
				if _, err := os.Stat(rotatedPath); os.IsNotExist(err) {
					_ = os.Rename(fullPath, rotatedPath)
					break
				}
			}
		}
	}

	f, err := os.OpenFile(fullPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, 0, err
	}

	currentInfo, _ := f.Stat()
	size := int64(0)
	if currentInfo != nil {
		size = currentInfo.Size()
	}

	return f, size, nil
}

// LogConnection writes a connection event across configured log outputs
func (l *MultiChannelLogger) LogConnection(conn monitor.TrackedConnection) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.rotateDayIfNeeded(conn.Timestamp); err != nil {
		return err
	}

	// 1. Write text format to network.log
	if l.networkFile != nil {
		ts := conn.Timestamp.Format(l.cfg.Logging.TimestampFormat)
		if ts == "" {
			ts = conn.Timestamp.Format("2006-01-02 15:04:05")
		}

		line := fmt.Sprintf("[%s] [%-8s] %-18s (PID: %-5d) -> %s:%-5d [%s] | Proto: %s | State: %s | Path: %s\n",
			ts,
			conn.Event,
			conn.ProcessName,
			conn.PID,
			conn.RemoteIP,
			conn.RemotePort,
			conn.Domain,
			conn.Protocol,
			conn.State,
			conn.ProcessPath,
		)

		n, _ := l.networkFile.WriteString(line)
		l.networkSize += int64(n)
		if l.networkSize >= l.maxSizeBytes {
			l.rotateCurrentFile(&l.networkFile, &l.networkSize, "network.log")
		}
	}

	// 2. Write JSON stream to connections.jsonl
	if l.jsonlFile != nil {
		data, err := json.Marshal(conn)
		if err == nil {
			data = append(data, '\n')
			n, _ := l.jsonlFile.Write(data)
			l.jsonlSize += int64(n)
			if l.jsonlSize >= l.maxSizeBytes {
				l.rotateCurrentFile(&l.jsonlFile, &l.jsonlSize, "connections.jsonl")
			}
		}
	}

	return nil
}

// LogAlert writes a security alert event to alerts.log
func (l *MultiChannelLogger) LogAlert(alt anomaly.Alert) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.rotateDayIfNeeded(alt.Timestamp); err != nil {
		return err
	}

	if l.alertsFile != nil {
		ts := alt.Timestamp.Format(l.cfg.Logging.TimestampFormat)
		if ts == "" {
			ts = alt.Timestamp.Format("2006-01-02 15:04:05")
		}

		detailBytes, _ := json.Marshal(alt.Details)

		line := fmt.Sprintf("[%s] [ALERT:%s] [%s] %s | Process: %s (%d) | Endpoint: %s (%s) | Details: %s\n",
			ts,
			alt.Level,
			alt.Type,
			alt.Message,
			alt.ProcessName,
			alt.PID,
			alt.Endpoint,
			alt.Domain,
			string(detailBytes),
		)

		n, _ := l.alertsFile.WriteString(line)
		l.alertsSize += int64(n)
		if l.alertsSize >= l.maxSizeBytes {
			l.rotateCurrentFile(&l.alertsFile, &l.alertsSize, "alerts.log")
		}
	}

	return nil
}

// LogSystem writes a system status or lifecycle message to network.log
func (l *MultiChannelLogger) LogSystem(msg string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if err := l.rotateDayIfNeeded(now); err != nil {
		return err
	}

	if l.networkFile != nil {
		ts := now.Format(l.cfg.Logging.TimestampFormat)
		if ts == "" {
			ts = now.Format("2006-01-02 15:04:05")
		}

		line := fmt.Sprintf("[%s] [SYSTEM  ] %s\n", ts, msg)
		n, _ := l.networkFile.WriteString(line)
		l.networkSize += int64(n)
		if l.networkSize >= l.maxSizeBytes {
			l.rotateCurrentFile(&l.networkFile, &l.networkSize, "network.log")
		}
	}

	return nil
}

func (l *MultiChannelLogger) rotateCurrentFile(file **os.File, size *int64, baseName string) {
	if *file != nil {
		_ = (*file).Close()
	}
	newF, newSize, _ := openLogFileWithRotation(l.dayDir, baseName, l.maxSizeBytes)
	*file = newF
	*size = newSize
}

func (l *MultiChannelLogger) closeFiles() {
	if l.networkFile != nil {
		_ = l.networkFile.Close()
		l.networkFile = nil
	}
	if l.alertsFile != nil {
		_ = l.alertsFile.Close()
		l.alertsFile = nil
	}
	if l.jsonlFile != nil {
		_ = l.jsonlFile.Close()
		l.jsonlFile = nil
	}
}

// Close gracefully closes all open log file descriptors
func (l *MultiChannelLogger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closeFiles()
}
