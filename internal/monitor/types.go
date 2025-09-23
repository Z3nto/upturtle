package monitor

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Type represents a monitor type.
type Type string

const (
	// TypeHTTP checks HTTP or HTTPS targets.
	TypeHTTP Type = "http"
	// TypeICMP checks hosts using ICMP echo requests.
	TypeICMP Type = "icmp"
)

// Status is the runtime state of a monitor.
type Status string

const (
	StatusUnknown Status = "unknown"
	StatusUp      Status = "up"
	StatusDown    Status = "down"
)

// CertValidationMode represents the certificate validation mode for HTTPS monitors.
type CertValidationMode string

const (
	// CertValidationFull performs full certificate validation (default)
	CertValidationFull CertValidationMode = "full"
	// CertValidationExpiryOnly only checks certificate expiry date
	CertValidationExpiryOnly CertValidationMode = "expiry_only"
	// CertValidationIgnore skips all certificate validation
	CertValidationIgnore CertValidationMode = "ignore"
)

// MonitorConfig describes the configuration for a monitor.
type MonitorConfig struct {
	ID             string        `json:"id"`
	Name           string        `json:"name"`
	Type           Type          `json:"type"`
	Target         string        `json:"target"`
	Interval       time.Duration `json:"interval"`
	Timeout        time.Duration `json:"timeout"`
	NotifyURL      string        `json:"notify_url"`
	NotificationID int           `json:"notification_id,omitempty"`
	Enabled        bool          `json:"enabled"`
	// GroupID is a stable identifier for the group (persisted)
	GroupID int    `json:"group_id,omitempty"`
	// Group defines a logical grouping by human-readable name for UI rendering
	Group  string `json:"group"`
	// Order specifies the order within its group (ascending)
	Order  int `json:"order"`
	// MasterID, when set, references another monitor that acts as a master.
	// If the master monitor is down, this monitor continues to run checks but
	// is labeled as "Master down" and does not send notifications.
	MasterID string `json:"master_id,omitempty"`
	// FailThreshold specifies after how many consecutive failures a DOWN
	// notification should be sent via the notifier. Defaults to 3 if not set
	// in forms; must be >= 1.
	FailThreshold int `json:"fail_threshold"`
	// CertValidation specifies the certificate validation mode for HTTPS monitors.
	// Only applies to HTTP monitors with HTTPS targets.
	CertValidation CertValidationMode `json:"cert_validation,omitempty"`
}

// CheckResult captures the outcome of a monitor check.
type CheckResult struct {
	Timestamp time.Time     `json:"timestamp"`
	Success   bool          `json:"success"`
	Latency   time.Duration `json:"latency"`
	Message   string        `json:"message"`
}

// Notification is emitted when a monitor changes its status.
type Notification struct {
	MonitorID   string
	MonitorName string
	Target      string
	Type        Type
	Status      Status
	Message     string
	Latency     time.Duration
	NotifyURL   string
}

// Notifier dispatches notifications to external systems.
type Notifier interface {
	Notify(Notification) error
}

// validateICMPTarget validates ICMP target to prevent command injection
func validateICMPTarget(target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return errors.New("target is required")
	}
	
	// Nur alphanumerische Zeichen, Punkte, Bindestriche und Doppelpunkte (für IPv6) erlauben
	// Keine Leerzeichen, Semikolons, Pipes oder andere Shell-Metazeichen
	validPattern := `^[a-zA-Z0-9.-:]+$`
	if matched, _ := regexp.MatchString(validPattern, target); !matched {
		return errors.New("icmp target contains invalid characters - only alphanumeric, dots, hyphens and colons allowed")
	}
	
	// Zusätzliche Längen-Validierung
	if len(target) > 253 {
		return errors.New("icmp target too long - maximum 253 characters")
	}
	
	// Prüfe auf gefährliche Sequenzen
	dangerousPatterns := []string{
		";", "|", "&", "$", "`", "$(", "||", "&&", 
		">>", "<<", ">", "<", "\\", "'", "\"",
	}
	for _, pattern := range dangerousPatterns {
		if strings.Contains(target, pattern) {
			return fmt.Errorf("icmp target contains dangerous sequence: %s", pattern)
		}
	}
	
	return nil
}

// Validate validates the monitor configuration.
func (c *MonitorConfig) Validate() error {
	if c.Name == "" {
		return errors.New("name is required")
	}
	switch c.Type {
	case TypeHTTP:
		if c.Target == "" {
			return errors.New("target is required")
		}
		parsed, err := url.Parse(c.Target)
		if err != nil {
			return fmt.Errorf("invalid http target: %w", err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return errors.New("http monitor requires http or https scheme")
		}
		if parsed.Host == "" {
			return errors.New("http monitor requires a host")
		}
	case TypeICMP:
		if err := validateICMPTarget(c.Target); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported monitor type: %s", c.Type)
	}
	if c.Interval <= 0 {
		return errors.New("interval must be greater than zero")
	}
	if c.Timeout <= 0 {
		return errors.New("timeout must be greater than zero")
	}
	if c.Timeout > c.Interval {
		return errors.New("timeout must not exceed interval")
	}
	if c.MasterID != "" && c.MasterID == c.ID {
		return errors.New("master_id must not reference itself")
	}
	if c.FailThreshold <= 0 {
		// normalize to sensible default
		c.FailThreshold = 3
	}
	return nil
}
