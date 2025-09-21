package database

import (
	"fmt"
)

// NewDatabase creates a new database instance based on the configuration
func NewDatabase(config Config) (Database, error) {
	switch config.Type {
	case DatabaseTypeSQLite:
		return NewSQLiteDB(config)
	case DatabaseTypeMySQL:
		// TODO: Implement MySQL support
		return nil, fmt.Errorf("MySQL support not yet implemented")
	default:
		return nil, fmt.Errorf("unsupported database type: %s", config.Type)
	}
}

// ValidateConfig validates the database configuration
func ValidateConfig(config Config) error {
	switch config.Type {
	case DatabaseTypeSQLite:
		if config.Path == "" {
			return fmt.Errorf("SQLite database path is required")
		}
		return nil
	case DatabaseTypeMySQL:
		if config.Host == "" {
			return fmt.Errorf("MySQL host is required")
		}
		if config.Database == "" {
			return fmt.Errorf("MySQL database name is required")
		}
		if config.Username == "" {
			return fmt.Errorf("MySQL username is required")
		}
		return nil
	default:
		return fmt.Errorf("unsupported database type: %s", config.Type)
	}
}
