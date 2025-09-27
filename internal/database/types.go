package database

import (
	"errors"
	"time"
)

// Common database errors
var (
	ErrDatabaseUnavailable = errors.New("database is not available")
)

// DatabaseType represents the type of database backend
type DatabaseType string

const (
	DatabaseTypeSQLite DatabaseType = "sqlite"
	DatabaseTypeMySQL  DatabaseType = "mysql"
)

// Config holds database configuration
type Config struct {
	Type     DatabaseType `json:"type"`
	Path     string       `json:"path,omitempty"`     // For SQLite
	Host     string       `json:"host,omitempty"`     // For MySQL
	Port     int          `json:"port,omitempty"`     // For MySQL
	Database string       `json:"database,omitempty"` // For MySQL
	Username string       `json:"username,omitempty"` // For MySQL
	Password string       `json:"password,omitempty"` // For MySQL
}

// HistoryData represents a single history record
type HistoryData struct {
	ID        int64         `json:"id"`
	MonitorID string        `json:"monitor_id"`
	Timestamp time.Time     `json:"timestamp"`
	Success   bool          `json:"success"`
	Latency   time.Duration `json:"latency"`
	Message   string        `json:"message"`
	Status    string        `json:"status"`
}

// MonitorData represents a monitor record in the database
type MonitorData struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Type           string    `json:"type"`
	Target         string    `json:"target"`
	IntervalSec    int       `json:"interval_seconds"`
	TimeoutSec     int       `json:"timeout_seconds"`
	NotificationID int       `json:"notification_id"`
	Enabled        bool      `json:"enabled"`
	GroupID        int       `json:"group_id"`
	Order          int       `json:"order"`
	MasterID       string    `json:"master_id"`
	FailThreshold  int       `json:"fail_threshold"`
	CertValidation string    `json:"cert_validation"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// GroupData represents a group record in the database
type GroupData struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Order     int       `json:"order"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NotificationData represents a notification record in the database
type NotificationData struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SettingData represents a setting record in the database
type SettingData struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Database interface defines the contract for database operations
type Database interface {
	// Initialize sets up the database connection and creates necessary tables
	Initialize() error

	// Close closes the database connection
	Close() error

	// Health checks if the database is accessible
	Health() error

	// Settings management
	SaveSetting(key, value string) error
	GetSetting(key string) (string, error)
	GetAllSettings() (map[string]string, error)
	DeleteSetting(key string) error

	// Monitor management
	SaveMonitor(monitor MonitorData) error
	GetMonitor(id string) (*MonitorData, error)
	GetAllMonitors() ([]MonitorData, error)
	DeleteMonitor(id string) error

	// Group management
	SaveGroup(group GroupData) (*GroupData, error) // Returns group with ID set
	GetGroup(id int) (*GroupData, error)
	GetAllGroups() ([]GroupData, error)
	DeleteGroup(id int) error

	// Notification management
	SaveNotification(notification NotificationData) (*NotificationData, error) // Returns notification with ID set
	GetNotification(id int) (*NotificationData, error)
	GetAllNotifications() ([]NotificationData, error)
	DeleteNotification(id int) error

	// History data operations
	SaveHistory(data HistoryData) error
	GetHistory(monitorID string, since time.Time) ([]HistoryData, error)
	GetLatestHistory(monitorID string) (*HistoryData, error)

	// Cleanup operations
	CleanupOldHistory(retentionDays int) error

	// Table management
	CreateHistoryTable(date time.Time) error
	DropHistoryTable(date time.Time) error
	ListHistoryTables() ([]time.Time, error)
}
