package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"upturtle/internal/config"
	"upturtle/internal/database"
	"upturtle/internal/monitor"
	"upturtle/internal/notifier"
	"upturtle/internal/server"
)

type appConfig struct {
	ListenAddr      string
	HistoryLimit    int
	RefreshInterval time.Duration
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}

	// Initialize Shoutrrr notifier; per-monitor NotifyURL determines destinations.
	var notif monitor.Notifier = notifier.NewShoutrrrNotifier()

	// Load persisted configuration (admin + monitors)
	configPath := os.Getenv("UPTURTLE_CONFIG_PATH")
	if configPath == "" {
		configPath = "/conf/config.json"
	}

	persisted, exists, err := config.Load(configPath)
	if err != nil {
		log.Printf("failed to load config file %s: %v", configPath, err)
	}

	// Admin credentials are sourced only from persisted config; env variables are ignored.

	manager := monitor.NewManager(cfg.HistoryLimit, notif)
	defer manager.Close()

	// Initialize database if configured
	var dbIntegration *monitor.DatabaseIntegration
	if exists && persisted.Database != nil {
		log.Printf("Initializing database: %s", persisted.Database.Type)
		
		if err := database.ValidateConfig(*persisted.Database); err != nil {
			log.Printf("Database configuration invalid: %v", err)
		} else {
			db, err := database.NewDatabase(*persisted.Database)
			if err != nil {
				log.Printf("Failed to create database: %v", err)
			} else {
				if err := db.Initialize(); err != nil {
					log.Printf("Failed to initialize database: %v", err)
				} else {
					dbIntegration = monitor.NewDatabaseIntegration(db)
					manager.SetDatabaseIntegration(dbIntegration)
					log.Printf("Database integration enabled")
				}
			}
		}
	}

	if exists {
		// Load configuration from database if available
		if persisted.Database != nil && manager.HasDatabaseIntegration() {
			if dbIntegration := manager.GetDatabaseIntegration(); dbIntegration != nil {
				db := dbIntegration.GetDatabase()
				log.Printf("Loading configurations from existing database connection...")
				
				// Load admin credentials if not set
				installRequired := (persisted.AdminUser == "" || persisted.AdminPasswordHash == "")
				if installRequired {
					var adminConfig map[string]interface{}
					if err := db.GetConfig("admin_credentials", &adminConfig); err == nil {
						if user, ok := adminConfig["username"].(string); ok && user != "" {
							if hash, ok := adminConfig["password_hash"].(string); ok && hash != "" {
								persisted.AdminUser = user
								persisted.AdminPasswordHash = hash
								log.Printf("Loaded admin credentials from database")
							}
						}
					}
				}
				
				// Load groups from database (override config file)
				var dbGroups []config.GroupConfig
				if err := db.GetConfig("groups", &dbGroups); err == nil && len(dbGroups) > 0 {
					persisted.Groups = dbGroups
					log.Printf("Loaded %d groups from database", len(dbGroups))
				}
				
				// Load notifications from database (override config file)
				var dbNotifications []config.NotificationConfig
				if err := db.GetConfig("notifications", &dbNotifications); err == nil && len(dbNotifications) > 0 {
					persisted.Notifications = dbNotifications
					log.Printf("Loaded %d notifications from database", len(dbNotifications))
				}
				
				// Load UI settings from database (only ShowMemoryDisplay). Debug flags must come from config file.
				var settings map[string]interface{}
				if err := db.GetConfig("settings", &settings); err == nil {
					if val, ok := settings["show_memory_display"].(bool); ok {
						persisted.ShowMemoryDisplay = val
					}
					log.Printf("Loaded UI settings from database")
				}
				
				// Load monitors from database (override config file)
				var dbMonitors []config.PersistedMonitorConfig
				if err := db.GetConfig("monitors", &dbMonitors); err == nil && len(dbMonitors) > 0 {
					persisted.Monitors = dbMonitors
					log.Printf("Loaded %d monitors from database", len(dbMonitors))
				}
			}
		}

		// Initialize monitors from file
		// Resolve NotifyURL from NotificationID if URL is not persisted
		idToURL := make(map[int]string, len(persisted.Notifications))
		for _, n := range persisted.Notifications {
			idToURL[n.ID] = strings.TrimSpace(n.URL)
		}
		mons := make([]monitor.MonitorConfig, 0, len(persisted.Monitors))
		for _, pm := range persisted.Monitors {
			cfg := pm.ToMonitorConfig()
			if cfg.NotificationID > 0 && strings.TrimSpace(cfg.NotifyURL) == "" {
				if u, ok := idToURL[cfg.NotificationID]; ok {
					cfg.NotifyURL = u
				}
			}
			mons = append(mons, cfg)
		}
		manager.LoadMonitors(mons)
	}

	// Installation page is required until admin credentials are set.
	installRequired := (persisted.AdminUser == "" || persisted.AdminPasswordHash == "")
	
	// Set default values for UI settings if not configured and no database is used
	if !exists {
		persisted.ShowMemoryDisplay = true // Default: enabled
		persisted.AuthDebug = true         // Default: enabled for debugging login issues
	}

	log.Printf("Creating server with %d groups, %d notifications, %d monitors", 
		len(persisted.Groups), len(persisted.Notifications), len(persisted.Monitors))
	
	srv, err := server.New(server.Config{
		Manager:           manager,
		AdminUser:         persisted.AdminUser,
		AdminPasswordHash: persisted.AdminPasswordHash,
		RefreshInterval:   cfg.RefreshInterval,
		Logger:            log.Default(),
		// Installation page is shown until admin credentials are configured
		InstallRequired:   installRequired,
		ConfigPath:        configPath,
		Groups:            append([]config.GroupConfig(nil), persisted.Groups...),
		Notifications:     append([]config.NotificationConfig(nil), persisted.Notifications...),
		MonitorDebug:      persisted.MonitorDebug,
		NotificationDebug: persisted.NotificationDebug,
		ApiDebug:          persisted.ApiDebug,
		AuthDebug:         persisted.AuthDebug,
		ShowMemoryDisplay: persisted.ShowMemoryDisplay,
		DatabaseConfig:    persisted.Database,
	})
	if err != nil {
		log.Fatalf("server init error: %v", err)
	}

	httpServer := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      srv,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("upturtle listening on %s", cfg.ListenAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Printf("shutdown signal received, stopping...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Close server and its database connections
	if err := srv.Close(); err != nil {
		log.Printf("server close error: %v", err)
	}
	
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("server shutdown error: %v", err)
	}
	// Manager is closed via defer.
}

func loadConfig() (appConfig, error) {
	cfg := appConfig{
		ListenAddr:      envDefault("LISTEN_ADDR", ":8080"),
		HistoryLimit:    envInt("HISTORY_LIMIT", 20),
		RefreshInterval: time.Duration(envInt("STATUS_REFRESH_SECONDS", 30)) * time.Second,
	}
	// Enforce a maximum of 20 historical entries per monitor in memory
	if cfg.HistoryLimit <= 0 {
		cfg.HistoryLimit = 20
	}
	if cfg.HistoryLimit > 20 {
		cfg.HistoryLimit = 20
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = 30 * time.Second
	}

	return cfg, nil
}

func envDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func envInt(key string, fallback int) int {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	v, err := strconv.Atoi(val)
	if err != nil {
		log.Printf("invalid value for %s: %v", key, err)
		return fallback
	}
	return v
}
