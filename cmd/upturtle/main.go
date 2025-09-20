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

	if exists {
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

	// Installation page is required until admin credentials are set in the persisted config.
	installRequired := (persisted.AdminUser == "" || persisted.AdminPasswordHash == "")

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
