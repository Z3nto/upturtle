package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"upturtle/internal/database"
	"upturtle/internal/monitor"
)

// AppConfig is the persisted application configuration.
// Password is stored as a bcrypt hash.
// Durations are persisted in whole seconds for readability.
type AppConfig struct {
	AdminUser         string                   `json:"admin_user"`
	AdminPasswordHash string                   `json:"admin_password_hash"`
	Monitors            []PersistedMonitorConfig `json:"monitors"`
	// Groups defines the order of monitor groups for UI display
	Groups []GroupConfig `json:"groups,omitempty"`
	// Notifications is the list of reusable notification targets (Shoutrrr URLs)
	Notifications []NotificationConfig `json:"notifications,omitempty"`
	// Database configuration - if set, measurement data will be stored in database
	Database *database.Config `json:"database,omitempty"`
	// Debug flags
	MonitorDebug      bool `json:"monitor_debug,omitempty"`
	NotificationDebug bool `json:"notification_debug,omitempty"`
	ApiDebug          bool `json:"api_debug,omitempty"`
	// UI settings
	ShowMemoryDisplay bool `json:"show_memory_display,omitempty"`
}

// GroupConfig defines a group with a stable integer ID and a name.
type GroupConfig struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	// Order controls the display ordering of groups. Lower values appear first.
	Order int `json:"order,omitempty"`
}

// NotificationConfig defines a reusable notification target
type NotificationConfig struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

// PersistedMonitorConfig mirrors monitor.MonitorConfig but uses seconds for durations.
type PersistedMonitorConfig struct {
	ID             string                   `json:"id"`
	Name           string                   `json:"name"`
	Type           monitor.Type             `json:"type"`
	Target         string                   `json:"target"`
	IntervalSec    int                      `json:"interval_seconds"`
	TimeoutSec     int                      `json:"timeout_seconds"`
	NotificationID int                      `json:"notification_id,omitempty"`
	Enabled        bool                     `json:"enabled"`
	GroupID        int                      `json:"group_id,omitempty"`
	Order          int                      `json:"order,omitempty"`
	MasterID       string                   `json:"master_id,omitempty"`
	FailThreshold  int                      `json:"fail_threshold"`
	CertValidation monitor.CertValidationMode `json:"cert_validation,omitempty"`
}

func FromMonitorConfig(m monitor.MonitorConfig) PersistedMonitorConfig {
	return PersistedMonitorConfig{
		ID:             m.ID,
		Name:           m.Name,
		Type:           m.Type,
		Target:         m.Target,
		IntervalSec:    int(m.Interval / time.Second),
		TimeoutSec:     int(m.Timeout / time.Second),
		NotificationID: m.NotificationID,
		Enabled:        m.Enabled,
		GroupID:        m.GroupID,
		Order:          m.Order,
		MasterID:       m.MasterID,
		FailThreshold:  m.FailThreshold,
		CertValidation: m.CertValidation,
	}
}

func (p PersistedMonitorConfig) ToMonitorConfig() monitor.MonitorConfig {
	interval := time.Duration(p.IntervalSec) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}
	timeout := time.Duration(p.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if timeout > interval {
		timeout = interval
	}
	return monitor.MonitorConfig{
		ID:             p.ID,
		Name:           p.Name,
		Type:           p.Type,
		Target:         p.Target,
		Interval:       interval,
		Timeout:        timeout,
		NotificationID: p.NotificationID,
		Enabled:        p.Enabled,
		GroupID:        p.GroupID,
		Order:          p.Order,
		MasterID:       p.MasterID,
		FailThreshold:  p.FailThreshold,
		CertValidation: p.CertValidation,
	}
}

// Load reads configuration from path. Returns (cfg, exists, error).
func Load(path string) (AppConfig, bool, error) {
	if path == "" {
		return AppConfig{}, false, errors.New("empty config path")
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return AppConfig{}, false, nil
		}
		return AppConfig{}, false, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return AppConfig{}, false, fmt.Errorf("read config: %w", err)
	}
	var cfg AppConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return AppConfig{}, false, fmt.Errorf("parse config: %w", err)
	}
	return cfg, true, nil
}

// Save writes configuration atomically to path. Creates parent directory if needed.
func Save(path string, cfg AppConfig) error {
	if path == "" {
		return errors.New("empty config path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("ensure config dir: %w", err)
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("atomic replace config: %w", err)
	}
	return nil
}
