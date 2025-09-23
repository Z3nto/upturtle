package monitor

import (
	"context"
	"errors"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ==== Types & Errors =====================================================
var (
	// ErrMonitorNotFound indicates that the requested monitor does not exist.
	ErrMonitorNotFound = errors.New("monitor not found")
)

type monitorEntry struct {
	config           MonitorConfig
	history          []CheckResult
	status           Status
	lastChecked      time.Time
	lastLatency      time.Duration
	lastMessage      string
	lastChange       time.Time
	cancel           context.CancelFunc
	lastNotification Status
	runID            uint64
	mu               sync.RWMutex
	// consecutiveFailures counts consecutive failed checks since the last success
	consecutiveFailures int
}

// ==== CRUD & Persistence ======================================================
// LoadMonitors initializes the manager with a set of pre-existing monitor
// configurations, preserving their IDs when provided. Enabled monitors will
// be started immediately. Invalid configs are skipped with a log message.
func (m *Manager) LoadMonitors(configs []MonitorConfig) {
	var maxID uint64
	for _, cfg := range configs {
		if err := cfg.Validate(); err != nil {
			log.Printf("skip invalid monitor config '%s': %v", cfg.Name, err)
			continue
		}
		// Respect cfg.Enabled as provided (do not force-enable here)

		if cfg.ID == "" {
			// Let AddMonitor assign a new ID for configs without one
			if _, err := m.AddMonitor(cfg); err != nil {
				log.Printf("failed to add monitor '%s': %v", cfg.Name, err)
			}
			continue
		}

		// Initialize history capacity based on database integration
		historyCapacity := m.historyLimit
		if m.dbIntegration != nil {
			// With database integration, don't pre-allocate memory for history
			historyCapacity = 0
		}
		
		entry := &monitorEntry{
			config:              cfg,
			history:             make([]CheckResult, 0, historyCapacity),
			status:              StatusUnknown,
			lastChange:          time.Now(),
			lastNotification:    StatusUp,
			consecutiveFailures: 0,
		}

		m.mu.Lock()
		m.monitors[cfg.ID] = entry
		m.mu.Unlock()

		if cfg.Enabled {
			m.startMonitor(entry)
		}

		// Track the maximum numeric ID to continue from on add.
		// Prefer whole-ID numeric parse. For legacy IDs like mon-YYYYMMDD-<n>,
		// fall back to parsing the numeric suffix.
		if n, err := strconv.ParseUint(cfg.ID, 10, 64); err == nil {
			if n > maxID {
				maxID = n
			}
		} else if dash := lastDash(cfg.ID); dash != -1 && dash+1 < len(cfg.ID) {
			if n2, err2 := strconv.ParseUint(cfg.ID[dash+1:], 10, 64); err2 == nil {
				if n2 > maxID {
					maxID = n2
				}
			}
		}
	}
	if maxID > 0 {
		atomic.StoreUint64(&m.idCounter, maxID)
	}
}

// GetAllConfigs returns shallow copies of all monitor configs for persistence.
func (m *Manager) GetAllConfigs() []MonitorConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]MonitorConfig, 0, len(m.monitors))
	for _, entry := range m.monitors {
		entry.mu.RLock()
		cfg := entry.config
		entry.mu.RUnlock()
		out = append(out, cfg)
	}
	return out
}

// ==== Utilities ===============================================================
// lastDash returns the last index of '-' in s, or -1 if not found.
func lastDash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '-' {
			return i
		}
	}
	return -1
}

// ==== Snapshots ===============================================================
// Snapshot represents an immutable copy of a monitor's runtime state.
type Snapshot struct {
	Config      MonitorConfig
	Status      Status
	LastChecked time.Time
	LastLatency time.Duration
	LastMessage string
	LastChange  time.Time
	History     []CheckResult
}

// ==== Manager: Fields =========================================================
// Manager coordinates monitors and keeps their history in memory.
type Manager struct {
	historyLimit int
	notifier     Notifier

	mu       sync.RWMutex
	monitors map[string]*monitorEntry

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	idCounter  uint64
	runCounter uint64
	// Debug flags
	MonitorDebug      bool
	NotificationDebug bool
	
	// Database integration (optional)
	dbIntegration *DatabaseIntegration
}

// ==== Manager: Constructor & Debug Flags =====================================
// NewManager creates a new manager.
func NewManager(historyLimit int, notifier Notifier) *Manager {
	if historyLimit <= 0 {
		historyLimit = 100
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		historyLimit: historyLimit,
		notifier:     notifier,
		monitors:     make(map[string]*monitorEntry),
		ctx:          ctx,
		cancel:       cancel,
	}
}

// SetMonitorDebug enables/disables verbose monitor debug logging.
func (m *Manager) SetMonitorDebug(v bool) { m.MonitorDebug = v }

// SetNotificationDebug enables/disables verbose notification debug logging.
func (m *Manager) SetNotificationDebug(v bool) { m.NotificationDebug = v }

// SetDatabaseIntegration enables database storage for measurement data
func (m *Manager) SetDatabaseIntegration(di *DatabaseIntegration) {
	m.dbIntegration = di
}

// GetDatabaseIntegration returns the current database integration
func (m *Manager) GetDatabaseIntegration() *DatabaseIntegration {
	return m.dbIntegration
}

// GetMemoryUsage returns statistics about memory usage
func (m *Manager) GetMemoryUsage() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	totalHistoryEntries := 0
	maxHistoryPerMonitor := 0
	
	for _, entry := range m.monitors {
		entry.mu.RLock()
		historyLen := len(entry.history)
		totalHistoryEntries += historyLen
		if historyLen > maxHistoryPerMonitor {
			maxHistoryPerMonitor = historyLen
		}
		entry.mu.RUnlock()
	}
	
	return map[string]interface{}{
		"total_monitors":           len(m.monitors),
		"total_history_entries":    totalHistoryEntries,
		"max_history_per_monitor":  maxHistoryPerMonitor,
		"database_integration":     m.dbIntegration != nil,
		"history_limit":           m.historyLimit,
	}
}

// HasDatabaseIntegration returns true if database integration is enabled
func (m *Manager) HasDatabaseIntegration() bool {
	return m.dbIntegration != nil
}

// IsDatabaseHealthy returns true if database is available (or no database is configured)
func (m *Manager) IsDatabaseHealthy() bool {
	if m.dbIntegration == nil {
		return true // No database configured, so "healthy" from perspective of availability
	}
	return m.dbIntegration.IsDatabaseHealthy()
}

// GetDatabaseError returns database error message if any
func (m *Manager) GetDatabaseError() string {
	if m.dbIntegration == nil {
		return ""
	}
	return m.dbIntegration.GetDatabaseError()
}

// GetHistoryFromDatabase retrieves measurement history from database for a monitor
func (m *Manager) GetHistoryFromDatabase(monitorID string, limit int) ([]CheckResult, error) {
	if m.dbIntegration == nil {
		return nil, nil // No database configured
	}
	
	// Get measurements from the last 24 hours
	since := time.Now().AddDate(0, 0, -1)
	return m.dbIntegration.GetMeasurements(monitorID, since, limit)
}

// ==== Lifecycle ===============================================================
// Close stops all running monitors.
func (m *Manager) Close() {
	m.cancel()
	m.mu.Lock()
	for _, entry := range m.monitors {
		entry.mu.Lock()
		if entry.cancel != nil {
			entry.cancel()
		}
		entry.mu.Unlock()
	}
	m.mu.Unlock()
	m.wg.Wait()
	
	// Close database integration if present
	if m.dbIntegration != nil {
		m.dbIntegration.Close()
	}
}

// ==== CRUD: Add/Update/Remove ================================================
// AddMonitor registers and starts a new monitor.
func (m *Manager) AddMonitor(cfg MonitorConfig) (MonitorConfig, error) {
	if err := cfg.Validate(); err != nil {
		return MonitorConfig{}, err
	}
	id := atomic.AddUint64(&m.idCounter, 1)
	cfg.ID = formatID(id)

	// Initialize history capacity based on database integration
	historyCapacity := m.historyLimit
	if m.dbIntegration != nil {
		// With database integration, don't pre-allocate memory for history
		historyCapacity = 0
	}
	
	entry := &monitorEntry{
		config:              cfg,
		history:             make([]CheckResult, 0, historyCapacity),
		status:              StatusUnknown,
		lastChange:          time.Now(),
		lastNotification:    StatusUp,
		consecutiveFailures: 0,
	}

	m.mu.Lock()
	m.monitors[cfg.ID] = entry
	m.mu.Unlock()

	if cfg.Enabled {
		m.startMonitor(entry)
	}

	return cfg, nil
}

// UpdateMonitor updates the configuration of an existing monitor.
func (m *Manager) UpdateMonitor(cfg MonitorConfig) (MonitorConfig, error) {
	if err := cfg.Validate(); err != nil {
		return MonitorConfig{}, err
	}
	if cfg.ID == "" {
		return MonitorConfig{}, ErrMonitorNotFound
	}

	m.mu.RLock()
	entry, ok := m.monitors[cfg.ID]
	m.mu.RUnlock()
	if !ok {
		return MonitorConfig{}, ErrMonitorNotFound
	}

	entry.mu.Lock()
	oldCfg := entry.config
	entry.config.Name = cfg.Name
	entry.config.Type = cfg.Type
	entry.config.Target = cfg.Target
	entry.config.Interval = cfg.Interval
	entry.config.Timeout = cfg.Timeout
	entry.config.NotifyURL = cfg.NotifyURL
	entry.config.NotificationID = cfg.NotificationID
	entry.config.Enabled = cfg.Enabled
	entry.config.GroupID = cfg.GroupID
	entry.config.Group = cfg.Group
	entry.config.Order = cfg.Order
	entry.config.MasterID = cfg.MasterID
	entry.config.FailThreshold = cfg.FailThreshold
	entry.config.CertValidation = cfg.CertValidation
	entry.mu.Unlock()

	needsRestart := oldCfg.Interval != cfg.Interval || oldCfg.Type != cfg.Type || oldCfg.Target != cfg.Target || oldCfg.Timeout != cfg.Timeout || oldCfg.Enabled != cfg.Enabled || oldCfg.CertValidation != cfg.CertValidation

	if needsRestart {
		entry.mu.Lock()
		cancel := entry.cancel
		entry.cancel = nil
		entry.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if cfg.Enabled {
			m.startMonitor(entry)
		} else {
			entry.mu.Lock()
			entry.status = StatusUnknown
			entry.lastMessage = ""
			entry.lastNotification = StatusUnknown
			entry.mu.Unlock()
		}
	}

	return cfg, nil
}

// RemoveMonitor removes a monitor completely.
func (m *Manager) RemoveMonitor(id string) error {
	m.mu.Lock()
	entry, ok := m.monitors[id]
	if ok {
		delete(m.monitors, id)
	}
	m.mu.Unlock()
	if !ok {
		return ErrMonitorNotFound
	}

	entry.mu.Lock()
	cancel := entry.cancel
	entry.cancel = nil
	entry.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	return nil
}

// ==== Accessors ===============================================================
// List returns snapshots of all monitors.
func (m *Manager) List() []Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	snapshots := make([]Snapshot, 0, len(m.monitors))
	for _, entry := range m.monitors {
		entry.mu.RLock()
		cfg := entry.config
		
		// Load history from database if available, otherwise use memory
		var historyCopy []CheckResult
		if m.dbIntegration != nil {
			// Load recent history from database (last 100 measurements)
			since := time.Now().Add(-24 * time.Hour)
			if dbHistory, err := m.dbIntegration.GetMeasurements(cfg.ID, since, 100); err == nil {
				// Use database history directly (already converted to CheckResult)
				historyCopy = dbHistory
			} else {
				// Fallback to memory if database fails
				historyCopy = make([]CheckResult, len(entry.history))
				copy(historyCopy, entry.history)
			}
		} else {
			// Use memory history
			historyCopy = make([]CheckResult, len(entry.history))
			copy(historyCopy, entry.history)
		}
		
		snapshot := Snapshot{
			Config:      cfg,
			Status:      entry.status,
			LastChecked: entry.lastChecked,
			LastLatency: entry.lastLatency,
			LastMessage: entry.lastMessage,
			LastChange:  entry.lastChange,
			History:     historyCopy,
		}
		entry.mu.RUnlock()
		snapshots = append(snapshots, snapshot)
	}
	return snapshots
}

// GetSnapshot returns the snapshot for a single monitor.
func (m *Manager) GetSnapshot(id string) (Snapshot, error) {
	m.mu.RLock()
	entry, ok := m.monitors[id]
	m.mu.RUnlock()
	if !ok {
		return Snapshot{}, ErrMonitorNotFound
	}

	entry.mu.RLock()
	defer entry.mu.RUnlock()

	// Load history from database if available, otherwise use memory
	var historyCopy []CheckResult
	if m.dbIntegration != nil {
		// Load recent history from database (last 100 measurements)
		since := time.Now().Add(-24 * time.Hour)
		if dbHistory, err := m.dbIntegration.GetMeasurements(id, since, 100); err == nil {
			// Use database history directly (already converted to CheckResult)
			historyCopy = dbHistory
		} else {
			// Fallback to memory if database fails
			historyCopy = make([]CheckResult, len(entry.history))
			copy(historyCopy, entry.history)
		}
	} else {
		// Use memory history
		historyCopy = make([]CheckResult, len(entry.history))
		copy(historyCopy, entry.history)
	}

	return Snapshot{
		Config:      entry.config,
		Status:      entry.status,
		LastChecked: entry.lastChecked,
		LastLatency: entry.lastLatency,
		LastMessage: entry.lastMessage,
		LastChange:  entry.lastChange,
		History:     historyCopy,
	}, nil
}

// ==== Runner =================================================================
func (m *Manager) startMonitor(entry *monitorEntry) {
	entry.mu.Lock()
	if entry.config.Interval <= 0 {
		entry.config.Interval = time.Second * 30
	}
	ctx, cancel := context.WithCancel(m.ctx)
	entry.cancel = cancel
	runID := atomic.AddUint64(&m.runCounter, 1)
	entry.runID = runID
	interval := entry.config.Interval
	entry.mu.Unlock()

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		defer func() {
			entry.mu.Lock()
			if entry.runID == runID {
				entry.cancel = nil
			}
			entry.mu.Unlock()
		}()

		// Perform an immediate check before waiting for the ticker.
		m.execute(entry)

		for {
			select {
			case <-ticker.C:
				m.execute(entry)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (m *Manager) execute(entry *monitorEntry) {
	entry.mu.RLock()
	cfg := entry.config
	entry.mu.RUnlock()

	if !cfg.Enabled {
		if m.MonitorDebug {
			log.Printf("[DEBUG] Monitor %s (%s) is disabled, skipping check", cfg.ID, cfg.Name)
		}
		return
	}

	if m.MonitorDebug {
		log.Printf("[DEBUG] Executing check for monitor %s (%s) - Type: %s, Target: %s",
			cfg.ID, cfg.Name, cfg.Type, cfg.Target)
	}

	var result CheckResult
	switch cfg.Type {
	case TypeHTTP:
		result = checkHTTP(cfg)
	case TypeICMP:
		result = checkICMP(cfg)
	default:
		result = CheckResult{
			Timestamp: time.Now(),
			Success:   false,
			Message:   "unsupported monitor type",
		}
		if m.MonitorDebug {
			log.Printf("[DEBUG] Unsupported monitor type: %s", cfg.Type)
		}
	}

	// Determine if master is configured and currently down
	masterDown := false
	if cfg.MasterID != "" {
		m.mu.RLock()
		master, ok := m.monitors[cfg.MasterID]
		m.mu.RUnlock()
		if ok {
			master.mu.RLock()
			masterStatus := master.status
			master.mu.RUnlock()
			if masterStatus == StatusDown {
				masterDown = true
			}
		}
	}

	// If master is down, prefix the result message so history also shows the label
	if masterDown {
		if result.Message != "" {
			result.Message = "[Master down] " + result.Message
		} else {
			result.Message = "[Master down]"
		}
	}

	entry.mu.Lock()
	prevStatus := entry.status
	if result.Success {
		entry.status = StatusUp
		entry.consecutiveFailures = 0
	} else {
		entry.status = StatusDown
		entry.consecutiveFailures++
	}
	// Store last message from (possibly prefixed) result
	entry.lastMessage = result.Message
	entry.lastChecked = result.Timestamp
	entry.lastLatency = result.Latency
	if entry.status != prevStatus {
		entry.lastChange = result.Timestamp
		if m.MonitorDebug {
			log.Printf("[DEBUG] Status change for %s (%s): %s -> %s, Message: %s",
				cfg.ID, cfg.Name, prevStatus, entry.status, result.Message)
		}
	}
	// Save to database if available, otherwise save to memory
	if m.dbIntegration != nil {
		// Database mode: only save to database, not to memory
		if err := m.dbIntegration.SaveMeasurement(cfg.ID, result, entry.status); err != nil {
			log.Printf("Failed to save measurement to database for %s: %v", cfg.ID, err)
			// Fallback to memory if database fails
			entry.history = append(entry.history, result)
			if len(entry.history) > m.historyLimit {
				excess := len(entry.history) - m.historyLimit
				copy(entry.history, entry.history[excess:])
				entry.history = entry.history[:m.historyLimit]
			}
		}
	} else {
		// Memory mode: save to memory
		entry.history = append(entry.history, result)
		if len(entry.history) > m.historyLimit {
			excess := len(entry.history) - m.historyLimit
			copy(entry.history, entry.history[excess:])
			entry.history = entry.history[:m.historyLimit]
		}
	}

	if m.MonitorDebug {
		log.Printf("[DEBUG] Check result for %s (%s): Success=%v, Status=%s, Latency=%v, Message=%s",
			cfg.ID, cfg.Name, result.Success, entry.status, result.Latency, result.Message)
	}

	// Determine if we should notify
	shouldNotify := false
	switch entry.status {
	case StatusDown:
		// Only notify when reaching the failure threshold and not already notified as DOWN
		threshold := cfg.FailThreshold
		if threshold <= 0 {
			threshold = 3
		}
		if entry.consecutiveFailures >= threshold && entry.lastNotification != StatusDown {
			shouldNotify = true
		}
	case StatusUp:
		// Notify on recovery if we had previously notified a DOWN (or anything not UP)
		if entry.lastNotification != StatusUp {
			shouldNotify = true
		}
	}
	// Suppress notifications if master is down
	if masterDown {
		shouldNotify = false
	}
	entry.mu.Unlock()

	if shouldNotify && m.notifier != nil {
		notifyURL := strings.TrimSpace(cfg.NotifyURL)
		if notifyURL == "" {
			if m.NotificationDebug {
				log.Printf("[DEBUG][NOTIFY] Skipping notification for %s (%s): no NotifyURL configured", cfg.ID, cfg.Name)
			}
			return
		}
		if m.NotificationDebug {
			log.Printf("[DEBUG][NOTIFY] Dispatching notification for %s (%s) -> status=%s url=%s",
				cfg.ID, cfg.Name, entry.status, notifyURL)
		}
		if err := m.notifier.Notify(Notification{
			MonitorID:   cfg.ID,
			MonitorName: cfg.Name,
			Target:      cfg.Target,
			Type:        cfg.Type,
			Status:      entry.status,
			Message:     entry.lastMessage,
			Latency:     result.Latency,
			NotifyURL:   notifyURL,
		}); err != nil {
			log.Printf("notification error for %s: %v", cfg.ID, err)
		} else {
			if m.NotificationDebug {
				log.Printf("[DEBUG][NOTIFY] Notification dispatched for %s (%s)", cfg.ID, cfg.Name)
			}
			// Mark as notified only after a successful dispatch
			entry.mu.Lock()
			entry.lastNotification = entry.status
			entry.mu.Unlock()
		}
	}
}

func formatID(id uint64) string {
	// Use strictly incremental numeric IDs represented as strings
	return strconv.FormatUint(id, 10)
}
