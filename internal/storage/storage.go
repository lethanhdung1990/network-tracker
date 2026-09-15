package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"network-tracker/internal/anomaly"
	"network-tracker/internal/monitor"
)

// Storage manages persistent SQLite database for connection history and security alerts
type Storage struct {
	db *sql.DB
}

// ReportSummary aggregates daily analytics data for CLI reporting
type ReportSummary struct {
	TotalConnections int
	UniqueProcesses  int
	TotalAlerts      int
	TopProcesses     []ProcessStat
	RecentAlerts     []anomaly.Alert
}

type ProcessStat struct {
	Name  string
	Count int
}

// NewStorage initializes SQLite database connection with WAL mode
func NewStorage(dbPath string) (*Storage, error) {
	if dbPath == "" {
		dbPath = "data/network_history.db"
	}

	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory %s: %w", dir, err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database %s: %w", dbPath, err)
	}

	// Optimize SQLite performance using WAL mode
	_, _ = db.Exec("PRAGMA journal_mode=WAL;")
	_, _ = db.Exec("PRAGMA synchronous=NORMAL;")

	s := &Storage{db: db}
	if err := s.initSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return s, nil
}

func (s *Storage) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS connections (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT NOT NULL,
		event TEXT NOT NULL,
		protocol TEXT NOT NULL,
		pid INTEGER NOT NULL,
		process_name TEXT NOT NULL,
		process_path TEXT,
		local_ip TEXT,
		local_port INTEGER,
		remote_ip TEXT,
		remote_port INTEGER,
		domain TEXT,
		state TEXT,
		upload_bps INTEGER,
		download_bps INTEGER
	);
	CREATE INDEX IF NOT EXISTS idx_conn_ts ON connections(timestamp);
	CREATE INDEX IF NOT EXISTS idx_conn_proc ON connections(process_name);

	CREATE TABLE IF NOT EXISTS alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT NOT NULL,
		level TEXT NOT NULL,
		type TEXT NOT NULL,
		message TEXT NOT NULL,
		process_name TEXT,
		pid INTEGER,
		endpoint TEXT,
		domain TEXT,
		details TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_alert_ts ON alerts(timestamp);
	`
	_, err := s.db.Exec(schema)
	return err
}

// SaveConnection records a socket event into the connections table
func (s *Storage) SaveConnection(conn monitor.TrackedConnection) error {
	query := `
	INSERT INTO connections (
		timestamp, event, protocol, pid, process_name, process_path,
		local_ip, local_port, remote_ip, remote_port, domain, state,
		upload_bps, download_bps
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := s.db.Exec(query,
		conn.Timestamp.Format("2006-01-02 15:04:05"),
		conn.Event,
		conn.Protocol,
		conn.PID,
		conn.ProcessName,
		conn.ProcessPath,
		conn.LocalIP,
		conn.LocalPort,
		conn.RemoteIP,
		conn.RemotePort,
		conn.Domain,
		conn.State,
		conn.UploadBps,
		conn.DownloadBps,
	)
	return err
}

// SaveAlert records a triggered security alert into the alerts table
func (s *Storage) SaveAlert(alt anomaly.Alert) error {
	detailsJSON, _ := json.Marshal(alt.Details)
	query := `
	INSERT INTO alerts (
		timestamp, level, type, message, process_name, pid, endpoint, domain, details
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := s.db.Exec(query,
		alt.Timestamp.Format("2006-01-02 15:04:05"),
		alt.Level,
		alt.Type,
		alt.Message,
		alt.ProcessName,
		alt.PID,
		alt.Endpoint,
		alt.Domain,
		string(detailsJSON),
	)
	return err
}

// GetReport queries summarized activity metrics for a specific date (YYYY-MM-DD)
func (s *Storage) GetReport(day string) (*ReportSummary, error) {
	if day == "" {
		day = time.Now().Format("2006-01-02")
	}
	pattern := day + "%"

	rep := &ReportSummary{}

	// 1. Total connection count and distinct processes
	_ = s.db.QueryRow("SELECT COUNT(*), COUNT(DISTINCT process_name) FROM connections WHERE timestamp LIKE ?", pattern).
		Scan(&rep.TotalConnections, &rep.UniqueProcesses)

	// 2. Total alerts count
	_ = s.db.QueryRow("SELECT COUNT(*) FROM alerts WHERE timestamp LIKE ?", pattern).
		Scan(&rep.TotalAlerts)

	// 3. Top 5 active processes by connection count
	rows, err := s.db.Query(`
		SELECT process_name, COUNT(*) as cnt
		FROM connections
		WHERE timestamp LIKE ?
		GROUP BY process_name
		ORDER BY cnt DESC
		LIMIT 5
	`, pattern)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ps ProcessStat
			if err := rows.Scan(&ps.Name, &ps.Count); err == nil {
				rep.TopProcesses = append(rep.TopProcesses, ps)
			}
		}
	}

	// 4. Most recent alerts
	alertRows, err := s.db.Query(`
		SELECT timestamp, level, type, message, process_name, pid, endpoint, domain, details
		FROM alerts
		WHERE timestamp LIKE ?
		ORDER BY id DESC
		LIMIT 10
	`, pattern)
	if err == nil {
		defer alertRows.Close()
		for alertRows.Next() {
			var alt anomaly.Alert
			var tsStr, detStr string
			if err := alertRows.Scan(&tsStr, &alt.Level, &alt.Type, &alt.Message, &alt.ProcessName, &alt.PID, &alt.Endpoint, &alt.Domain, &detStr); err == nil {
				alt.Timestamp, _ = time.Parse("2006-01-02 15:04:05", tsStr)
				_ = json.Unmarshal([]byte(detStr), &alt.Details)
				rep.RecentAlerts = append(rep.RecentAlerts, alt)
			}
		}
	}

	return rep, nil
}

// CleanupOldRecords purges entries older than the retention threshold
func (s *Storage) CleanupOldRecords(retentionDays int) error {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays).Format("2006-01-02 15:04:05")

	_, err := s.db.Exec("DELETE FROM connections WHERE timestamp < ?", cutoff)
	if err != nil {
		return err
	}
	_, err = s.db.Exec("DELETE FROM alerts WHERE timestamp < ?", cutoff)
	return err
}

// Close safely closes the database connection
func (s *Storage) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
