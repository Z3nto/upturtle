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

// Database interface defines the contract for database operations
type Database interface {
	// Initialize sets up the database connection and creates necessary tables
	Initialize() error

	// Close closes the database connection
	Close() error

	// Health checks if the database is accessible
	Health() error

	// Configuration management
	SaveConfig(key string, value interface{}) error
	GetConfig(key string, dest interface{}) error
	DeleteConfig(key string) error

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
