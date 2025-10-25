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

// GroupType represents the type of group
type GroupType string

const (
	GroupTypeDefault    GroupType = "default"    // Default groups for main status page
	GroupTypeStatusPage GroupType = "statuspage" // Groups specific to status pages
)

// GroupData represents a group record in the database
type GroupData struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Type      GroupType `json:"type"`
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

// StatusPageData represents a status page record in the database
type StatusPageData struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`      // URL path segment
	Active    bool      `json:"active"`    // Whether the page is accessible
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// StatusPageMonitorData represents the many-to-many relationship between status pages and monitors
type StatusPageMonitorData struct {
	ID           int       `json:"id"`
	StatusPageID int       `json:"status_page_id"`
	MonitorID    string    `json:"monitor_id"`
	GroupID      int       `json:"group_id"`      // Can reference existing or statuspage-specific groups
	Order        int       `json:"order"`         // Display order within the group
	CreatedAt    time.Time `json:"created_at"`
}

// UserRole represents the role/permission level of a user
type UserRole string

const (
	UserRoleReadOnly UserRole = "readonly" // Can only access main status page
	UserRoleWrite    UserRole = "write"    // Can access admin, notifications, status pages
	UserRoleAdmin    UserRole = "admin"    // Can access everything including user management
)

// UserData represents a user record in the database
type UserData struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	Role         UserRole  `json:"role"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// RememberMeToken represents a persistent login token
type RememberMeToken struct {
	ID           int       `json:"id"`
	UserID       int       `json:"user_id"`
	Selector     string    `json:"selector"`      // Public identifier (stored in cookie)
	TokenHash    string    `json:"token_hash"`    // Hashed validator (stored in DB)
	ExpiresAt    time.Time `json:"expires_at"`
	LastUsedAt   time.Time `json:"last_used_at"`
	CreatedAt    time.Time `json:"created_at"`
	UserAgent    string    `json:"user_agent"`    // For identifying device
	IPAddress    string    `json:"ip_address"`    // For security logging
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
	GetGroupsByType(groupType GroupType) ([]GroupData, error)
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

	// Status page management
	SaveStatusPage(page StatusPageData) (*StatusPageData, error) // Returns page with ID set
	GetStatusPage(id int) (*StatusPageData, error)
	GetStatusPageBySlug(slug string) (*StatusPageData, error)
	GetAllStatusPages() ([]StatusPageData, error)
	DeleteStatusPage(id int) error

	// Status page monitor management
	AddMonitorToStatusPage(data StatusPageMonitorData) error
	RemoveMonitorFromStatusPage(statusPageID int, monitorID string) error
	GetStatusPageMonitors(statusPageID int) ([]StatusPageMonitorData, error)
	ClearStatusPageMonitors(statusPageID int) error

	// User management
	SaveUser(user UserData) (*UserData, error) // Returns user with ID set
	GetUser(id int) (*UserData, error)
	GetUserByUsername(username string) (*UserData, error)
	GetAllUsers() ([]UserData, error)
	DeleteUser(id int) error

	// Remember-me token management
	SaveRememberMeToken(token RememberMeToken) (*RememberMeToken, error)
	GetRememberMeToken(selector string) (*RememberMeToken, error)
	UpdateRememberMeTokenLastUsed(id int, lastUsed time.Time) error
	DeleteRememberMeToken(id int) error
	DeleteRememberMeTokensByUser(userID int) error
	CleanupExpiredRememberMeTokens() error
}
