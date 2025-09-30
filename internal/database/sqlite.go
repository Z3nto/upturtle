package database

import (
	"database/sql"
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

	// Create normalized tables
	if err := s.createMonitorsTable(); err != nil {
		return fmt.Errorf("failed to create monitors table: %w", err)
	}

	if err := s.createGroupsTable(); err != nil {
		return fmt.Errorf("failed to create groups table: %w", err)
	}

	if err := s.createNotificationsTable(); err != nil {
		return fmt.Errorf("failed to create notifications table: %w", err)
	}

	if err := s.createSettingsTable(); err != nil {
		return fmt.Errorf("failed to create settings table: %w", err)
	}

	if err := s.createStatusPagesTable(); err != nil {
		return fmt.Errorf("failed to create status_pages table: %w", err)
	}

	if err := s.createStatusPageMonitorsTable(); err != nil {
		return fmt.Errorf("failed to create status_page_monitors table: %w", err)
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


// createMonitorsTable creates the monitors table
func (s *SQLiteDB) createMonitorsTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS monitors (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		target TEXT NOT NULL,
		interval_sec INTEGER NOT NULL,
		timeout_sec INTEGER NOT NULL,
		notification_id INTEGER DEFAULT 0,
		enabled BOOLEAN NOT NULL DEFAULT 1,
		group_id INTEGER DEFAULT 0,
		order_num INTEGER DEFAULT 0,
		master_id TEXT,
		fail_threshold INTEGER NOT NULL DEFAULT 3,
		cert_validation TEXT DEFAULT 'full',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	_, err := s.db.Exec(query)
	if err != nil {
		return err
	}

	// Create indexes
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_monitors_group_id ON monitors(group_id)`,
		`CREATE INDEX IF NOT EXISTS idx_monitors_enabled ON monitors(enabled)`,
		`CREATE INDEX IF NOT EXISTS idx_monitors_order ON monitors(group_id, order_num)`,
	}

	for _, indexQuery := range indexes {
		if _, err := s.db.Exec(indexQuery); err != nil {
			log.Printf("Warning: Failed to create monitor index: %v", err)
		}
	}

	return nil
}

// createGroupsTable creates the groups table
func (s *SQLiteDB) createGroupsTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS groups (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		type TEXT NOT NULL DEFAULT 'default',
		order_num INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(name, type)
	)`

	_, err := s.db.Exec(query)
	if err != nil {
		return err
	}

	// Create indexes
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_groups_order ON groups(order_num)`,
		`CREATE INDEX IF NOT EXISTS idx_groups_type ON groups(type)`,
	}

	for _, indexQuery := range indexes {
		if _, err := s.db.Exec(indexQuery); err != nil {
			log.Printf("Warning: Failed to create groups index: %v", err)
		}
	}

	return nil
}

// createNotificationsTable creates the notifications table
func (s *SQLiteDB) createNotificationsTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS notifications (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		url TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	_, err := s.db.Exec(query)
	return err
}

// createSettingsTable creates the settings table
func (s *SQLiteDB) createSettingsTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	_, err := s.db.Exec(query)
	return err
}

// createStatusPagesTable creates the status_pages table
func (s *SQLiteDB) createStatusPagesTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS status_pages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		slug TEXT NOT NULL UNIQUE,
		active BOOLEAN NOT NULL DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	_, err := s.db.Exec(query)
	if err != nil {
		return err
	}

	// Create index
	_, err = s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_status_pages_slug ON status_pages(slug)`)
	if err != nil {
		log.Printf("Warning: Failed to create status_pages index: %v", err)
	}

	return nil
}

// createStatusPageMonitorsTable creates the status_page_monitors table
func (s *SQLiteDB) createStatusPageMonitorsTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS status_page_monitors (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		status_page_id INTEGER NOT NULL,
		monitor_id TEXT NOT NULL,
		group_id INTEGER NOT NULL,
		order_num INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (status_page_id) REFERENCES status_pages(id) ON DELETE CASCADE,
		UNIQUE(status_page_id, monitor_id)
	)`

	_, err := s.db.Exec(query)
	if err != nil {
		return err
	}

	// Create indexes
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_spm_status_page ON status_page_monitors(status_page_id)`,
		`CREATE INDEX IF NOT EXISTS idx_spm_monitor ON status_page_monitors(monitor_id)`,
		`CREATE INDEX IF NOT EXISTS idx_spm_group ON status_page_monitors(group_id)`,
	}

	for _, indexQuery := range indexes {
		if _, err := s.db.Exec(indexQuery); err != nil {
			log.Printf("Warning: Failed to create status_page_monitors index: %v", err)
		}
	}

	return nil
}


// Settings management methods

// SaveSetting saves a setting value
func (s *SQLiteDB) SaveSetting(key, value string) error {
	query := `
	INSERT OR REPLACE INTO settings (key, value, updated_at) 
	VALUES (?, ?, CURRENT_TIMESTAMP)`

	_, err := s.db.Exec(query, key, value)
	return err
}

// GetSetting retrieves a setting value
func (s *SQLiteDB) GetSetting(key string) (string, error) {
	var value string
	query := `SELECT value FROM settings WHERE key = ?`

	err := s.db.QueryRow(query, key).Scan(&value)
	return value, err
}

// GetAllSettings retrieves all settings
func (s *SQLiteDB) GetAllSettings() (map[string]string, error) {
	query := `SELECT key, value FROM settings`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	settings := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		settings[key] = value
	}

	return settings, rows.Err()
}

// DeleteSetting deletes a setting
func (s *SQLiteDB) DeleteSetting(key string) error {
	query := `DELETE FROM settings WHERE key = ?`
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

// Monitor management methods

// SaveMonitor saves a monitor record
func (s *SQLiteDB) SaveMonitor(monitor MonitorData) error {
	query := `
	INSERT OR REPLACE INTO monitors (
		id, name, type, target, interval_sec, timeout_sec, notification_id,
		enabled, group_id, order_num, master_id, fail_threshold, cert_validation,
		created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
		COALESCE((SELECT created_at FROM monitors WHERE id = ?), CURRENT_TIMESTAMP),
		CURRENT_TIMESTAMP)`

	_, err := s.db.Exec(query,
		monitor.ID, monitor.Name, monitor.Type, monitor.Target,
		monitor.IntervalSec, monitor.TimeoutSec, monitor.NotificationID,
		monitor.Enabled, monitor.GroupID, monitor.Order, monitor.MasterID,
		monitor.FailThreshold, monitor.CertValidation, monitor.ID)

	return err
}

// GetMonitor retrieves a monitor by ID
func (s *SQLiteDB) GetMonitor(id string) (*MonitorData, error) {
	query := `
	SELECT id, name, type, target, interval_sec, timeout_sec, notification_id,
		   enabled, group_id, order_num, master_id, fail_threshold, cert_validation,
		   created_at, updated_at
	FROM monitors WHERE id = ?`

	var monitor MonitorData
	err := s.db.QueryRow(query, id).Scan(
		&monitor.ID, &monitor.Name, &monitor.Type, &monitor.Target,
		&monitor.IntervalSec, &monitor.TimeoutSec, &monitor.NotificationID,
		&monitor.Enabled, &monitor.GroupID, &monitor.Order, &monitor.MasterID,
		&monitor.FailThreshold, &monitor.CertValidation,
		&monitor.CreatedAt, &monitor.UpdatedAt)

	if err != nil {
		return nil, err
	}

	return &monitor, nil
}

// GetAllMonitors retrieves all monitors
func (s *SQLiteDB) GetAllMonitors() ([]MonitorData, error) {
	query := `
	SELECT id, name, type, target, interval_sec, timeout_sec, notification_id,
		   enabled, group_id, order_num, master_id, fail_threshold, cert_validation,
		   created_at, updated_at
	FROM monitors ORDER BY group_id, order_num, name`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var monitors []MonitorData
	for rows.Next() {
		var monitor MonitorData
		err := rows.Scan(
			&monitor.ID, &monitor.Name, &monitor.Type, &monitor.Target,
			&monitor.IntervalSec, &monitor.TimeoutSec, &monitor.NotificationID,
			&monitor.Enabled, &monitor.GroupID, &monitor.Order, &monitor.MasterID,
			&monitor.FailThreshold, &monitor.CertValidation,
			&monitor.CreatedAt, &monitor.UpdatedAt)
		if err != nil {
			return nil, err
		}
		monitors = append(monitors, monitor)
	}

	return monitors, rows.Err()
}

// DeleteMonitor deletes a monitor
func (s *SQLiteDB) DeleteMonitor(id string) error {
	query := `DELETE FROM monitors WHERE id = ?`
	_, err := s.db.Exec(query, id)
	return err
}

// Group management methods

// SaveGroup saves a group record
func (s *SQLiteDB) SaveGroup(group GroupData) (*GroupData, error) {
	// Default to "default" type if not specified
	if group.Type == "" {
		group.Type = GroupTypeDefault
	}

	if group.ID == 0 {
		// Insert new group
		query := `
		INSERT INTO groups (name, type, order_num, created_at, updated_at)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`

		result, err := s.db.Exec(query, group.Name, group.Type, group.Order)
		if err != nil {
			return nil, err
		}

		id, err := result.LastInsertId()
		if err != nil {
			return nil, err
		}

		group.ID = int(id)
	} else {
		// Update existing group
		query := `
		UPDATE groups 
		SET name = ?, type = ?, order_num = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`

		_, err := s.db.Exec(query, group.Name, group.Type, group.Order, group.ID)
		if err != nil {
			return nil, err
		}
	}

	// Fetch the complete record
	return s.GetGroup(group.ID)
}

// GetGroup retrieves a group by ID
func (s *SQLiteDB) GetGroup(id int) (*GroupData, error) {
	query := `
	SELECT id, name, type, order_num, created_at, updated_at
	FROM groups WHERE id = ?`

	var group GroupData
	err := s.db.QueryRow(query, id).Scan(
		&group.ID, &group.Name, &group.Type, &group.Order,
		&group.CreatedAt, &group.UpdatedAt)

	if err != nil {
		return nil, err
	}

	return &group, nil
}

// GetAllGroups retrieves all groups
func (s *SQLiteDB) GetAllGroups() ([]GroupData, error) {
	query := `
	SELECT id, name, type, order_num, created_at, updated_at
	FROM groups ORDER BY type, order_num, name`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []GroupData
	for rows.Next() {
		var group GroupData
		err := rows.Scan(
			&group.ID, &group.Name, &group.Type, &group.Order,
			&group.CreatedAt, &group.UpdatedAt)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}

	return groups, rows.Err()
}

// GetGroupsByType retrieves groups filtered by type
func (s *SQLiteDB) GetGroupsByType(groupType GroupType) ([]GroupData, error) {
	query := `
	SELECT id, name, type, order_num, created_at, updated_at
	FROM groups WHERE type = ? ORDER BY order_num, name`

	rows, err := s.db.Query(query, groupType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []GroupData
	for rows.Next() {
		var group GroupData
		err := rows.Scan(
			&group.ID, &group.Name, &group.Type, &group.Order,
			&group.CreatedAt, &group.UpdatedAt)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}

	return groups, rows.Err()
}

// DeleteGroup deletes a group
func (s *SQLiteDB) DeleteGroup(id int) error {
	query := `DELETE FROM groups WHERE id = ?`
	_, err := s.db.Exec(query, id)
	return err
}

// Notification management methods

// SaveNotification saves a notification record
func (s *SQLiteDB) SaveNotification(notification NotificationData) (*NotificationData, error) {
	if notification.ID == 0 {
		// Insert new notification
		query := `
		INSERT INTO notifications (name, url, created_at, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`

		result, err := s.db.Exec(query, notification.Name, notification.URL)
		if err != nil {
			return nil, err
		}

		id, err := result.LastInsertId()
		if err != nil {
			return nil, err
		}

		notification.ID = int(id)
	} else {
		// Update existing notification
		query := `
		UPDATE notifications 
		SET name = ?, url = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`

		_, err := s.db.Exec(query, notification.Name, notification.URL, notification.ID)
		if err != nil {
			return nil, err
		}
	}

	// Fetch the complete record
	return s.GetNotification(notification.ID)
}

// GetNotification retrieves a notification by ID
func (s *SQLiteDB) GetNotification(id int) (*NotificationData, error) {
	query := `
	SELECT id, name, url, created_at, updated_at
	FROM notifications WHERE id = ?`

	var notification NotificationData
	err := s.db.QueryRow(query, id).Scan(
		&notification.ID, &notification.Name, &notification.URL,
		&notification.CreatedAt, &notification.UpdatedAt)

	if err != nil {
		return nil, err
	}

	return &notification, nil
}

// GetAllNotifications retrieves all notifications
func (s *SQLiteDB) GetAllNotifications() ([]NotificationData, error) {
	query := `
	SELECT id, name, url, created_at, updated_at
	FROM notifications ORDER BY name`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notifications []NotificationData
	for rows.Next() {
		var notification NotificationData
		err := rows.Scan(
			&notification.ID, &notification.Name, &notification.URL,
			&notification.CreatedAt, &notification.UpdatedAt)
		if err != nil {
			return nil, err
		}
		notifications = append(notifications, notification)
	}

	return notifications, rows.Err()
}

// DeleteNotification deletes a notification
func (s *SQLiteDB) DeleteNotification(id int) error {
	query := `DELETE FROM notifications WHERE id = ?`
	_, err := s.db.Exec(query, id)
	return err
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

// Status page management methods

// SaveStatusPage saves a status page record
func (s *SQLiteDB) SaveStatusPage(page StatusPageData) (*StatusPageData, error) {
	if page.ID == 0 {
		// Insert new status page
		query := `
		INSERT INTO status_pages (name, slug, active, created_at, updated_at)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`

		result, err := s.db.Exec(query, page.Name, page.Slug, page.Active)
		if err != nil {
			return nil, err
		}

		id, err := result.LastInsertId()
		if err != nil {
			return nil, err
		}

		page.ID = int(id)
	} else {
		// Update existing status page
		query := `
		UPDATE status_pages 
		SET name = ?, slug = ?, active = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`

		_, err := s.db.Exec(query, page.Name, page.Slug, page.Active, page.ID)
		if err != nil {
			return nil, err
		}
	}

	// Fetch the complete record
	return s.GetStatusPage(page.ID)
}

// GetStatusPage retrieves a status page by ID
func (s *SQLiteDB) GetStatusPage(id int) (*StatusPageData, error) {
	query := `
	SELECT id, name, slug, active, created_at, updated_at
	FROM status_pages WHERE id = ?`

	var page StatusPageData
	err := s.db.QueryRow(query, id).Scan(
		&page.ID, &page.Name, &page.Slug, &page.Active,
		&page.CreatedAt, &page.UpdatedAt)

	if err != nil {
		return nil, err
	}

	return &page, nil
}

// GetStatusPageBySlug retrieves a status page by slug
func (s *SQLiteDB) GetStatusPageBySlug(slug string) (*StatusPageData, error) {
	query := `
	SELECT id, name, slug, active, created_at, updated_at
	FROM status_pages WHERE slug = ?`

	var page StatusPageData
	err := s.db.QueryRow(query, slug).Scan(
		&page.ID, &page.Name, &page.Slug, &page.Active,
		&page.CreatedAt, &page.UpdatedAt)

	if err != nil {
		return nil, err
	}

	return &page, nil
}

// GetAllStatusPages retrieves all status pages
func (s *SQLiteDB) GetAllStatusPages() ([]StatusPageData, error) {
	query := `
	SELECT id, name, slug, active, created_at, updated_at
	FROM status_pages ORDER BY name`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pages []StatusPageData
	for rows.Next() {
		var page StatusPageData
		err := rows.Scan(
			&page.ID, &page.Name, &page.Slug, &page.Active,
			&page.CreatedAt, &page.UpdatedAt)
		if err != nil {
			return nil, err
		}
		pages = append(pages, page)
	}

	return pages, rows.Err()
}

// DeleteStatusPage deletes a status page
func (s *SQLiteDB) DeleteStatusPage(id int) error {
	// Foreign key cascade will automatically delete related status_page_monitors
	query := `DELETE FROM status_pages WHERE id = ?`
	_, err := s.db.Exec(query, id)
	return err
}

// Status page monitor management methods

// AddMonitorToStatusPage adds a monitor to a status page
func (s *SQLiteDB) AddMonitorToStatusPage(data StatusPageMonitorData) error {
	query := `
	INSERT OR REPLACE INTO status_page_monitors (status_page_id, monitor_id, group_id, order_num, created_at)
	VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`

	_, err := s.db.Exec(query, data.StatusPageID, data.MonitorID, data.GroupID, data.Order)
	return err
}

// RemoveMonitorFromStatusPage removes a monitor from a status page
func (s *SQLiteDB) RemoveMonitorFromStatusPage(statusPageID int, monitorID string) error {
	query := `DELETE FROM status_page_monitors WHERE status_page_id = ? AND monitor_id = ?`
	_, err := s.db.Exec(query, statusPageID, monitorID)
	return err
}

// GetStatusPageMonitors retrieves all monitors for a status page
func (s *SQLiteDB) GetStatusPageMonitors(statusPageID int) ([]StatusPageMonitorData, error) {
	query := `
	SELECT id, status_page_id, monitor_id, group_id, order_num, created_at
	FROM status_page_monitors 
	WHERE status_page_id = ?
	ORDER BY group_id, order_num`

	rows, err := s.db.Query(query, statusPageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var monitors []StatusPageMonitorData
	for rows.Next() {
		var monitor StatusPageMonitorData
		err := rows.Scan(
			&monitor.ID, &monitor.StatusPageID, &monitor.MonitorID,
			&monitor.GroupID, &monitor.Order, &monitor.CreatedAt)
		if err != nil {
			return nil, err
		}
		monitors = append(monitors, monitor)
	}

	return monitors, rows.Err()
}

// ClearStatusPageMonitors removes all monitors from a status page
func (s *SQLiteDB) ClearStatusPageMonitors(statusPageID int) error {
	query := `DELETE FROM status_page_monitors WHERE status_page_id = ?`
	_, err := s.db.Exec(query, statusPageID)
	return err
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
