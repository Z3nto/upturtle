package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// SQLiteDB implements the Database interface using SQLite
type SQLiteDB struct {
	db   *sql.DB
	path string
}

// NewSQLiteDB creates a new SQLite database instance
func NewSQLiteDB(config Config) (*SQLiteDB, error) {
	if config.Path == "" {
		return nil, fmt.Errorf("SQLite database path is required")
	}

	return &SQLiteDB{
		path: config.Path,
	}, nil
}

// Initialize sets up the SQLite database connection and creates necessary tables
func (s *SQLiteDB) Initialize() error {
	// Ensure directory exists
	dir := filepath.Dir(s.path)
	if err := ensureDir(dir); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}

	// Open database connection
	db, err := sql.Open("sqlite3", s.path+"?_journal_mode=WAL&_timeout=5000")
	if err != nil {
		return fmt.Errorf("failed to open SQLite database: %w", err)
	}

	s.db = db

	// Create configuration table
	if err := s.createConfigTable(); err != nil {
		return fmt.Errorf("failed to create config table: %w", err)
	}

	// Create history tables for today
	today := time.Now()

	if err := s.CreateHistoryTable(today); err != nil {
		return fmt.Errorf("failed to create today's history table: %w", err)
	}

	log.Printf("SQLite database initialized at %s", s.path)
	return nil
}

// Close closes the database connection
func (s *SQLiteDB) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Health checks if the database is accessible
func (s *SQLiteDB) Health() error {
	if s.db == nil {
		return fmt.Errorf("database connection is nil")
	}

	return s.db.Ping()
}

// createConfigTable creates the configuration table
func (s *SQLiteDB) createConfigTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS config (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	_, err := s.db.Exec(query)
	return err
}

// SaveConfig saves a configuration value
func (s *SQLiteDB) SaveConfig(key string, value interface{}) error {
	jsonValue, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal config value: %w", err)
	}

	query := `
	INSERT OR REPLACE INTO config (key, value, updated_at) 
	VALUES (?, ?, CURRENT_TIMESTAMP)`

	_, err = s.db.Exec(query, key, string(jsonValue))
	return err
}

// GetConfig retrieves a configuration value
func (s *SQLiteDB) GetConfig(key string, dest interface{}) error {
	var jsonValue string
	query := `SELECT value FROM config WHERE key = ?`

	err := s.db.QueryRow(query, key).Scan(&jsonValue)
	if err != nil {
		return err
	}

	return json.Unmarshal([]byte(jsonValue), dest)
}

// DeleteConfig deletes a configuration value
func (s *SQLiteDB) DeleteConfig(key string) error {
	query := `DELETE FROM config WHERE key = ?`
	_, err := s.db.Exec(query, key)
	return err
}

// CreateHistoryTable creates a history table for a specific date
func (s *SQLiteDB) CreateHistoryTable(date time.Time) error {
	tableName := s.getHistoryTableName(date)

	query := fmt.Sprintf(`
	CREATE TABLE IF NOT EXISTS %s (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		monitor_id TEXT NOT NULL,
		timestamp DATETIME NOT NULL,
		success BOOLEAN NOT NULL,
		latency_ns INTEGER NOT NULL,
		message TEXT,
		status TEXT NOT NULL
	)`, tableName)

	_, err := s.db.Exec(query)
	if err != nil {
		return err
	}

	// Create indexes for better performance
	indexQueries := []string{
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_%s_monitor_id ON %s(monitor_id)`,
			tableName, tableName),
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_%s_timestamp ON %s(timestamp)`,
			tableName, tableName),
	}

	for _, indexQuery := range indexQueries {
		if _, err := s.db.Exec(indexQuery); err != nil {
			// Log but don't fail on index creation errors
			log.Printf("Warning: Failed to create index: %v", err)
		}
	}

	return nil
}

// DropHistoryTable drops a history table for a specific date
func (s *SQLiteDB) DropHistoryTable(date time.Time) error {
	tableName := s.getHistoryTableName(date)
	query := fmt.Sprintf(`DROP TABLE IF EXISTS %s`, tableName)

	_, err := s.db.Exec(query)
	if err == nil {
		log.Printf("Dropped history table: %s", tableName)
	}
	return err
}

// ListHistoryTables returns all history table dates
func (s *SQLiteDB) ListHistoryTables() ([]time.Time, error) {
	query := `
	SELECT name FROM sqlite_master 
	WHERE type='table' AND name LIKE 'history_%'
	ORDER BY name`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var dates []time.Time
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			continue
		}

		// Extract date from table name (history_YYYYMMDD)
		if len(tableName) >= 20 { // "history_" + "YYYYMMDD"
			dateStr := tableName[13:] // Skip "history_"
			if date, err := time.Parse("20060102", dateStr); err == nil {
				dates = append(dates, date)
			}
		}
	}

	return dates, rows.Err()
}

// SaveHistory saves a history record
func (s *SQLiteDB) SaveHistory(data HistoryData) error {
	tableName := s.getHistoryTableName(data.Timestamp)

	// Ensure table exists for this date
	if err := s.CreateHistoryTable(data.Timestamp); err != nil {
		return fmt.Errorf("failed to ensure history table exists: %w", err)
	}

	query := fmt.Sprintf(`
	INSERT INTO %s (monitor_id, timestamp, success, latency_ns, message, status)
	VALUES (?, ?, ?, ?, ?, ?)`, tableName)

	_, err := s.db.Exec(query,
		data.MonitorID,
		data.Timestamp.UTC(),
		data.Success,
		data.Latency.Nanoseconds(),
		data.Message,
		string(data.Status))

	return err
}

// GetHistory retrieves history for a monitor since a specific time
func (s *SQLiteDB) GetHistory(monitorID string, since time.Time) ([]HistoryData, error) {
	// Get all relevant tables (from since date to today)
	tables, err := s.getRelevantTables(since, time.Now())
	if err != nil {
		return nil, err
	}

	var allHistory []HistoryData

	for _, tableName := range tables {
		query := fmt.Sprintf(`
		SELECT id, monitor_id, timestamp, success, latency_ns, message, status
		FROM %s 
		WHERE monitor_id = ? AND timestamp >= ?
		ORDER BY timestamp ASC`, tableName)

		rows, err := s.db.Query(query, monitorID, since.UTC())
		if err != nil {
			// Table might not exist, skip it
			continue
		}

		history, err := s.scanHistory(rows)
		rows.Close()
		if err != nil {
			return nil, err
		}

		allHistory = append(allHistory, history...)
	}

	return allHistory, nil
}

// GetLatestHistory retrieves the latest history for a monitor
func (s *SQLiteDB) GetLatestHistory(monitorID string) (*HistoryData, error) {
	// Check today's table first, then yesterday's
	today := time.Now()
	yesterday := today.AddDate(0, 0, -1)

	tables := []string{
		s.getHistoryTableName(today),
		s.getHistoryTableName(yesterday),
	}

	for _, tableName := range tables {
		query := fmt.Sprintf(`
		SELECT id, monitor_id, timestamp, success, latency_ns, message, status
		FROM %s 
		WHERE monitor_id = ?
		ORDER BY timestamp DESC
		LIMIT 1`, tableName)

		var data HistoryData
		var latencyNs int64
		var status string

		err := s.db.QueryRow(query, monitorID).Scan(
			&data.ID,
			&data.MonitorID,
			&data.Timestamp,
			&data.Success,
			&latencyNs,
			&data.Message,
			&status,
		)

		if err == nil {
			data.Latency = time.Duration(latencyNs)
			data.Status = status
			return &data, nil
		}

		if err != sql.ErrNoRows {
			return nil, err
		}
	}

	return nil, sql.ErrNoRows
}

// CleanupOldHistory removes history data older than retentionDays
func (s *SQLiteDB) CleanupOldHistory(retentionDays int) error {
	cutoffDate := time.Now().AddDate(0, 0, -retentionDays)

	tables, err := s.ListHistoryTables()
	if err != nil {
		return err
	}

	droppedCount := 0
	for _, tableDate := range tables {
		if tableDate.Before(cutoffDate) {
			if err := s.DropHistoryTable(tableDate); err != nil {
				log.Printf("Failed to drop old history table for %s: %v",
					tableDate.Format("2006-01-02"), err)
			} else {
				droppedCount++
			}
		}
	}

	if droppedCount > 0 {
		log.Printf("Cleaned up %d old history tables", droppedCount)
	}

	return nil
}

// Helper methods

func (s *SQLiteDB) getHistoryTableName(date time.Time) string {
	return fmt.Sprintf("history_%s", date.Format("20060102"))
}

func (s *SQLiteDB) getRelevantTables(since, until time.Time) ([]string, error) {
	var tables []string

	// Generate table names for each day in the range
	current := since.Truncate(24 * time.Hour)
	end := until.Truncate(24*time.Hour).AddDate(0, 0, 1) // Include until date

	for current.Before(end) {
		tables = append(tables, s.getHistoryTableName(current))
		current = current.AddDate(0, 0, 1)
	}

	return tables, nil
}

func (s *SQLiteDB) scanHistory(rows *sql.Rows) ([]HistoryData, error) {
	var history []HistoryData

	for rows.Next() {
		var data HistoryData
		var latencyNs int64
		var status string

		err := rows.Scan(
			&data.ID,
			&data.MonitorID,
			&data.Timestamp,
			&data.Success,
			&latencyNs,
			&data.Message,
			&status,
		)
		if err != nil {
			return nil, err
		}

		data.Latency = time.Duration(latencyNs)
		data.Status = status
		history = append(history, data)
	}

	return history, rows.Err()
}

// ensureDir creates directory if it doesn't exist
func ensureDir(dir string) error {
	if dir == "" || dir == "." {
		return nil
	}

	if strings.Contains(dir, "..") {
		return fmt.Errorf("directory path contains '..'")
	}

	return os.MkdirAll(dir, 0755)
}
