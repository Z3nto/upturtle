package monitor

import (
	"context"
	"log"
	"sync"
	"time"

	"upturtle/internal/database"
)

// DatabaseIntegration handles database operations for monitor data
type DatabaseIntegration struct {
	db            database.Database
	dbHealthy     bool
	dbHealthMu    sync.RWMutex
	cleanupTicker *time.Ticker
	cleanupDone   chan struct{}
	retentionDays int
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewDatabaseIntegration creates a new database integration
func NewDatabaseIntegration(db database.Database) *DatabaseIntegration {
	ctx, cancel := context.WithCancel(context.Background())

	di := &DatabaseIntegration{
		db:            db,
		dbHealthy:     true,
		cleanupDone:   make(chan struct{}),
		retentionDays: 1, // Default: keep data for 1 day (today + yesterday)
		ctx:           ctx,
		cancel:        cancel,
	}

	// Start database health monitoring
	go di.monitorDatabaseHealth()

	// Start cleanup scheduler
	go di.scheduleCleanup()

	return di
}

// GetDatabase returns the underlying database connection
func (di *DatabaseIntegration) GetDatabase() database.Database {
	return di.db
}

// SetRetentionDays sets how many days of history data to keep
func (di *DatabaseIntegration) SetRetentionDays(days int) {
	if days < 1 {
		days = 1
	}
	di.retentionDays = days
}

// Close stops the database integration
func (di *DatabaseIntegration) Close() {
	di.cancel()

	// Stop cleanup scheduler
	if di.cleanupTicker != nil {
		di.cleanupTicker.Stop()
	}
	close(di.cleanupDone)

	// Close database connection
	if di.db != nil {
		if err := di.db.Close(); err != nil {
			log.Printf("Error closing database: %v", err)
		}
	}
}

// IsDatabaseHealthy returns whether the database is currently accessible
func (di *DatabaseIntegration) IsDatabaseHealthy() bool {
	di.dbHealthMu.RLock()
	defer di.dbHealthMu.RUnlock()
	return di.dbHealthy
}

// GetDatabaseError returns the last database error message, if any
func (di *DatabaseIntegration) GetDatabaseError() string {
	if di.IsDatabaseHealthy() {
		return ""
	}
	return "Database connection is not available"
}

// SaveHistory saves a history result to the database
func (di *DatabaseIntegration) SaveHistory(monitorID string, result CheckResult, status Status) error {
	if !di.IsDatabaseHealthy() {
		return database.ErrDatabaseUnavailable
	}

	history := database.HistoryData{
		MonitorID: monitorID,
		Timestamp: result.Timestamp,
		Success:   result.Success,
		Latency:   result.Latency,
		Message:   result.Message,
		Status:    string(status),
	}

	return di.db.SaveHistory(history)
}

// GetHistory retrieves history from the database
func (di *DatabaseIntegration) GetHistory(monitorID string, since time.Time, limit int) ([]CheckResult, error) {
	if !di.IsDatabaseHealthy() {
		return nil, database.ErrDatabaseUnavailable
	}

	history, err := di.db.GetHistory(monitorID, since)
	if err != nil {
		return nil, err
	}

	// Convert database history to CheckResults
	results := make([]CheckResult, 0, len(history))
	for _, m := range history {
		results = append(results, CheckResult{
			Timestamp: m.Timestamp,
			Success:   m.Success,
			Latency:   m.Latency,
			Message:   m.Message,
		})
	}

	// Apply limit if specified
	if limit > 0 && len(results) > limit {
		results = results[len(results)-limit:]
	}

	return results, nil
}

// GetLatestHistory retrieves the latest history for a monitor
func (di *DatabaseIntegration) GetLatestHistory(monitorID string) (*CheckResult, error) {
	if !di.IsDatabaseHealthy() {
		return nil, database.ErrDatabaseUnavailable
	}

	history, err := di.db.GetLatestHistory(monitorID)
	if err != nil {
		return nil, err
	}

	return &CheckResult{
		Timestamp: history.Timestamp,
		Success:   history.Success,
		Latency:   history.Latency,
		Message:   history.Message,
	}, nil
}

// SaveConfig saves configuration to the database
func (di *DatabaseIntegration) SaveConfig(key string, value interface{}) error {
	if !di.IsDatabaseHealthy() {
		return database.ErrDatabaseUnavailable
	}

	return di.db.SaveConfig(key, value)
}

// GetConfig retrieves configuration from the database
func (di *DatabaseIntegration) GetConfig(key string, dest interface{}) error {
	if !di.IsDatabaseHealthy() {
		return database.ErrDatabaseUnavailable
	}

	return di.db.GetConfig(key, dest)
}

// monitorDatabaseHealth periodically checks database connectivity
func (di *DatabaseIntegration) monitorDatabaseHealth() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			healthy := true
			if err := di.db.Health(); err != nil {
				healthy = false
				log.Printf("Database health check failed: %v", err)
			}

			di.dbHealthMu.Lock()
			wasHealthy := di.dbHealthy
			di.dbHealthy = healthy
			di.dbHealthMu.Unlock()

			// Log status changes
			if wasHealthy && !healthy {
				log.Printf("Database became unavailable")
			} else if !wasHealthy && healthy {
				log.Printf("Database connection restored")
			}

		case <-di.ctx.Done():
			return
		}
	}
}

// scheduleCleanup runs cleanup tasks on schedule
func (di *DatabaseIntegration) scheduleCleanup() {
	// Run initial cleanup
	di.performCleanup()

	// Calculate time until next 00:01
	now := time.Now()
	next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 1, 0, 0, now.Location())
	initialDelay := next.Sub(now)

	// Wait for first 00:01, then run daily
	select {
	case <-time.After(initialDelay):
		di.performCleanup()
	case <-di.cleanupDone:
		return
	}

	// Set up daily ticker
	di.cleanupTicker = time.NewTicker(24 * time.Hour)
	defer di.cleanupTicker.Stop()

	for {
		select {
		case <-di.cleanupTicker.C:
			di.performCleanup()
		case <-di.cleanupDone:
			return
		}
	}
}

// performCleanup removes old history data
func (di *DatabaseIntegration) performCleanup() {
	if !di.IsDatabaseHealthy() {
		log.Printf("Skipping cleanup: database not available")
		return
	}

	log.Printf("Starting history data cleanup (retention: %d days)", di.retentionDays)

	if err := di.db.CleanupOldHistory(di.retentionDays); err != nil {
		log.Printf("Cleanup failed: %v", err)
	} else {
		log.Printf("Cleanup completed successfully")
	}
}
