package server

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"upturtle/internal/config"
	"upturtle/internal/database"
	"upturtle/internal/monitor"
	"upturtle/internal/notifier"
)

// Embed static assets so they are always available regardless of working directory.
//
//go:embed static/*
var staticFS embed.FS

// normalizeShoutrrrURL cleans up known shoutrrr URL variants.
// For example, Discord supports both discord://TOKEN@ID and users sometimes append
// a trailing '/webhook' which Shoutrrr rejects. This removes such suffixes.
func normalizeShoutrrrURL(u string) string {
	s := strings.TrimSpace(u)
	if s == "" {
		return s
	}

	low := strings.ToLower(s)
	if strings.HasPrefix(low, "discord://") {
		if strings.HasSuffix(low, "/webhook") {
			// remove trailing /webhook exactly as typed (preserve original casing up to trim)
			if strings.HasSuffix(s, "/webhook") {
				s = strings.TrimSuffix(s, "/webhook")
			} else {
				// if casing differs, trim based on length
				s = s[:len(s)-len("/webhook")]
			}
		}
	}
	return s
}

// ==== Utilities ===============================================================

// newStaticHandler returns a handler that serves files from the embedded static FS,
// falling back to the on-disk path during development. If logo.png is requested but
// missing, it will attempt to serve logo.svg instead.
func newStaticHandler() http.Handler {
	var fsys fs.FS
	if sub, err := fs.Sub(staticFS, "static"); err == nil {
		fsys = sub
	} else {
		fsys = os.DirFS("internal/server/static")
	}
	fileServer := http.FileServer(http.FS(fsys))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "logo.png" {
			if f, err := fsys.Open("logo.png"); err == nil {
				_ = f.Close()
			} else {
				if svg, err2 := fsys.Open("logo.svg"); err2 == nil {
					defer svg.Close()
					w.Header().Set("Content-Type", "image/svg+xml")
					_, _ = io.Copy(w, svg)
					return
				}
			}
		}
		fileServer.ServeHTTP(w, r)
	})
}

// ==== Types & Constructor =====================================================

// APISnapshot represents a monitor snapshot for API responses with converted time units
type APISnapshot struct {
	Config      APIMonitorConfig `json:"config"`
	Status      string           `json:"status"`
	LastChecked time.Time        `json:"last_checked"`
	LastLatency int64            `json:"last_latency"` // in milliseconds
	LastMessage string           `json:"last_message"`
	LastChange  time.Time        `json:"last_change"`
}

// APIMonitorConfig represents monitor configuration for API responses with converted time units
type APIMonitorConfig struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Type            string `json:"type"`
	Target          string `json:"target"`
	IntervalSeconds int    `json:"interval_seconds"` // converted from nanoseconds
	TimeoutSeconds  int    `json:"timeout_seconds"`  // converted from nanoseconds
	Enabled         bool   `json:"enabled"`
	Group           string `json:"group"`
	GroupID         int    `json:"group_id"`
	Order           int    `json:"order"`
	MasterID        string `json:"master_id"`
	NotificationID  int    `json:"notification_id"`
	FailThreshold   int    `json:"fail_threshold"`
	CertValidation  string `json:"cert_validation"`
}

// APICheckResult represents a check result for API responses with converted time units
type APICheckResult struct {
	Timestamp time.Time `json:"timestamp"`
	Success   bool      `json:"success"`
	Latency   int64     `json:"latency"` // in milliseconds
	Message   string    `json:"message"`
}

// convertCheckResultToAPI converts internal check result to API format
func convertCheckResultToAPI(result monitor.CheckResult) APICheckResult {
	return APICheckResult{
		Timestamp: result.Timestamp,
		Success:   result.Success,
		Latency:   result.Latency.Nanoseconds() / 1000000, // convert to milliseconds
		Message:   result.Message,
	}
}

// convertSnapshotToAPI converts internal snapshot to API format
func convertSnapshotToAPI(snap monitor.Snapshot) APISnapshot {
	return APISnapshot{
		Config: APIMonitorConfig{
			ID:              snap.Config.ID,
			Name:            snap.Config.Name,
			Type:            string(snap.Config.Type),
			Target:          snap.Config.Target,
			IntervalSeconds: int(snap.Config.Interval.Seconds()),
			TimeoutSeconds:  int(snap.Config.Timeout.Seconds()),
			Enabled:         snap.Config.Enabled,
			Group:           snap.Config.Group,
			GroupID:         snap.Config.GroupID,
			Order:           snap.Config.Order,
			MasterID:        snap.Config.MasterID,
			NotificationID:  snap.Config.NotificationID,
			FailThreshold:   snap.Config.FailThreshold,
			CertValidation:  string(snap.Config.CertValidation),
		},
		Status:      string(snap.Status),
		LastChecked: snap.LastChecked,
		LastLatency: snap.LastLatency.Nanoseconds() / 1000000, // convert to milliseconds
		LastMessage: snap.LastMessage,
		LastChange:  snap.LastChange,
	}
}

// Server exposes HTTP endpoints for the uptime monitor.
type Server struct {
	manager         *monitor.Manager
	templates       *template.Template
	adminUser       string
	adminPassword   string
	refreshInterval time.Duration
	logger          *log.Logger
	mux             *http.ServeMux
	installRequired bool
	configPath      string
	// simple in-memory session store: sessionID -> expiry
	sessions map[string]time.Time
	// CSRF token store: sessionID -> token
	csrfTokens map[string]string
	// ordered list of groups for display in UI
	groups []config.GroupConfig
	// list of predefined notifications for selection
	notifications []config.NotificationConfig
	// next ID counters
	nextGroupID        int
	nextNotificationID int
	// debug flags (also persisted)
	monitorDebug      bool
	notificationDebug bool
	apiDebug          bool
	authDebug         bool
	// UI settings
	showMemoryDisplay bool
	// database configuration
	databaseConfig *database.Config
	// persistent database connection (only for config storage)
	configDB database.Database
}

// Config holds the parameters for creating a server instance.
type Config struct {
	Manager           *monitor.Manager
	AdminUser         string
	AdminPasswordHash string
	RefreshInterval   time.Duration
	Logger            *log.Logger
	// When true, the server will require an installation step to set admin
	// credentials and write the initial configuration file.
	InstallRequired bool
	// Path to the JSON configuration file for persistence.
	ConfigPath string
	// Groups defines the preferred display order of monitor groups
	Groups []config.GroupConfig
	// Notifications are predefined Shoutrrr targets available for selection
	Notifications []config.NotificationConfig
	// Debug flags (persisted in config file)
	MonitorDebug      bool
	NotificationDebug bool
	ApiDebug          bool
	AuthDebug         bool
	// UI settings
	ShowMemoryDisplay bool
	// Database configuration
	DatabaseConfig *database.Config
}

// New constructs a new HTTP server with the provided configuration.
func New(cfg Config) (*Server, error) {
	if cfg.Manager == nil {
		return nil, errors.New("manager is required")
	}

	templates, err := loadTemplates()
	if err != nil {
		return nil, err
	}

	refresh := cfg.RefreshInterval
	if refresh <= 0 {
		refresh = 30 * time.Second
	}

	s := &Server{
		manager:           cfg.Manager,
		templates:         templates,
		adminUser:         cfg.AdminUser,
		refreshInterval:   refresh,
		logger:            cfg.Logger,
		mux:               http.NewServeMux(),
		installRequired:   cfg.InstallRequired,
		groups:            append([]config.GroupConfig(nil), cfg.Groups...),
		notifications:     append([]config.NotificationConfig(nil), cfg.Notifications...),
		configPath:        cfg.ConfigPath,
		monitorDebug:      cfg.MonitorDebug,
		notificationDebug: cfg.NotificationDebug,
		apiDebug:          cfg.ApiDebug,
		authDebug:         cfg.AuthDebug,
		showMemoryDisplay: cfg.ShowMemoryDisplay,
		databaseConfig:    cfg.DatabaseConfig,
	}

	// Initialize persistent database connection if configured
	// Reuse the database connection from the manager if available
	if cfg.DatabaseConfig != nil {
		if dbIntegration := cfg.Manager.GetDatabaseIntegration(); dbIntegration != nil {
			// Reuse existing database connection from manager
			s.configDB = dbIntegration.GetDatabase()
			s.logger.Printf("Reusing database connection from manager for config storage")
		} else {
			// Create new connection if manager doesn't have one
			if db, err := database.NewDatabase(*cfg.DatabaseConfig); err == nil {
				if err := db.Initialize(); err == nil {
					s.configDB = db
					s.logger.Printf("Persistent database connection established for config storage")
				} else {
					s.logger.Printf("Warning: Failed to initialize config database: %v", err)
				}
			} else {
				s.logger.Printf("Warning: Failed to create config database: %v", err)
			}
		}
	}

	// initialize session store
	s.sessions = make(map[string]time.Time)
	// initialize CSRF token store
	s.csrfTokens = make(map[string]string)
	// normalize group orders if missing and sort by Order
	s.normalizeAndSortGroups()
	// compute next counters from existing config
	for _, g := range s.groups {
		if g.ID >= s.nextGroupID {
			s.nextGroupID = g.ID + 1
		}
	}
	for _, n := range s.notifications {
		if n.ID >= s.nextNotificationID {
			s.nextNotificationID = n.ID + 1
		}
	}
	if s.logger == nil {
		s.logger = log.Default()
	}
	if cfg.AdminPasswordHash != "" {
		s.adminPassword = cfg.AdminPasswordHash
	}

	// Start periodic cleanup of expired sessions and CSRF tokens
	s.startSessionCleanup()

	s.routes()
	// Apply debug flags to manager on startup
	if s.manager != nil {
		s.manager.SetMonitorDebug(s.monitorDebug)
		s.manager.SetNotificationDebug(s.notificationDebug)
	}
	notifier.ConfigureDebugLogging(s.notificationDebug)
	return s, nil
}

// authDebugf logs authentication debug messages if auth debugging is enabled
func (s *Server) authDebugf(format string, args ...interface{}) {
	if s.authDebug {
		s.logger.Printf("[AUTH DEBUG] "+format, args...)
	}
}

// Close closes the server and its database connections
func (s *Server) Close() error {
	if s.configDB != nil {
		return s.configDB.Close()
	}
	return nil
}

// getGroupName returns the name for a given group ID, or "" if not found.
func (s *Server) getGroupName(id int) string {
	for _, g := range s.groups {
		if g.ID == id {
			return g.Name
		}
	}
	return ""
}

// ==== View Models & Helpers ===================================================

// buildAdminData constructs the data model for the admin page, including
// grouping, ordering, and computing MasterDown flags.
func (s *Server) buildAdminData(r *http.Request, success, failure string) AdminPageData {
	snapshots := s.manager.List()
	// Build status map for master dependency
	statusByID := make(map[string]monitor.Status, len(snapshots))
	for _, snap := range snapshots {
		statusByID[snap.Config.ID] = snap.Status
	}
	grouped := map[int][]AdminMonitorView{}
	for _, snap := range snapshots {
		g := snap.Config.GroupID
		v := toAdminMonitorView(snap)
		if v.MasterID != "" {
			if st, ok := statusByID[v.MasterID]; ok {
				v.MasterDown = st == monitor.StatusDown
			}
		}
		grouped[g] = append(grouped[g], v)
	}
	// Ensure groups in preferred order, include any new groups at the end
	orderedIDs := make([]int, 0, len(s.groups))
	seen := map[int]bool{}
	for _, gg := range s.groups {
		orderedIDs = append(orderedIDs, gg.ID)
		seen[gg.ID] = true
	}
	for g := range grouped {
		if !seen[g] {
			orderedIDs = append(orderedIDs, g)
		}
	}
	groups := make([]AdminGroupView, 0, len(orderedIDs))
	for _, g := range orderedIDs {
		mons := grouped[g]
		sort.Slice(mons, func(i, j int) bool {
			if mons[i].Order == mons[j].Order {
				return mons[i].Name < mons[j].Name
			}
			return mons[i].Order < mons[j].Order
		})
		groups = append(groups, AdminGroupView{ID: g, Name: s.getGroupName(g), Monitors: mons})
	}
	return AdminPageData{
		BasePageData: BasePageData{
			Title:             "Administration",
			ContentTemplate:   "admin.content",
			CSRFToken:         s.getCSRFToken(r),
			DatabaseEnabled:   s.manager.HasDatabaseIntegration(),
			DatabaseHealthy:   s.manager.IsDatabaseHealthy(),
			DatabaseError:     s.manager.GetDatabaseError(),
			ShowMemoryDisplay: s.showMemoryDisplay,
		},
		Groups:        groups,
		Notifications: s.notifications,
		Error:         failure,
		Success:       success,
	}
}

// ==== Admin Pages =============================================================

// handleAdmin renders the admin UI (render-only; actions go through REST)
func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data := s.buildAdminData(r, r.URL.Query().Get("success"), r.URL.Query().Get("error"))
	if err := s.templates.ExecuteTemplate(w, "admin.gohtml", data); err != nil {
		s.logger.Printf("admin template error: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// ---- Settings page ----
// handleAdminSettings renders the settings page (GET only).
func (s *Server) handleAdminSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data := struct {
		BasePageData
		MonitorDebug      bool
		NotificationDebug bool
		ApiDebug          bool
		AuthDebug         bool
		ShowMemoryDisplay bool
		Error             string
		Success           string
	}{
		BasePageData: BasePageData{
			Title:           "Settings",
			ContentTemplate: "settings.content",
			CSRFToken:       s.getCSRFToken(r),
		},
		MonitorDebug:      s.monitorDebug,
		NotificationDebug: s.notificationDebug,
		ApiDebug:          s.apiDebug,
		AuthDebug:         s.authDebug,
		ShowMemoryDisplay: s.showMemoryDisplay,
		Error:             r.URL.Query().Get("error"),
		Success:           r.URL.Query().Get("success"),
	}
	if err := s.templates.ExecuteTemplate(w, "settings.gohtml", data); err != nil {
		s.logger.Printf("settings template error: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// ==== API: Settings ===========================================================

// handleAPISettings handles PUT requests to update application settings
func (s *Server) handleAPISettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.apiDebug {
		s.logger.Printf("[API DEBUG] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	}

	// First check authentication
	if !s.ensureAuth(w, r) {
		return
	}

	var body struct {
		MonitorDebug      bool   `json:"monitor_debug"`
		NotificationDebug bool   `json:"notification_debug"`
		ApiDebug          bool   `json:"api_debug"`
		AuthDebug         bool   `json:"auth_debug"`
		ShowMemoryDisplay bool   `json:"show_memory_display"`
		CSRFToken         string `json:"csrf_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Validate CSRF token from JSON body
	if !s.validateCSRFTokenFromJSON(r, body.CSRFToken) {
		http.Error(w, "CSRF token validation failed", http.StatusForbidden)
		return
	}

	s.monitorDebug = body.MonitorDebug
	s.notificationDebug = body.NotificationDebug
	s.apiDebug = body.ApiDebug
	s.authDebug = body.AuthDebug
	s.showMemoryDisplay = body.ShowMemoryDisplay

	if s.manager != nil {
		s.manager.SetMonitorDebug(body.MonitorDebug)
		s.manager.SetNotificationDebug(body.NotificationDebug)
	}
	notifier.ConfigureDebugLogging(body.NotificationDebug)

	if err := s.saveConfig(); err != nil {
		s.logger.Printf("persist after settings update: %v", err)
		http.Error(w, "failed to save settings", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ==== API: Monitors ===========================================================

// Unified API wrappers: delegate to collection or item handlers based on path remainder
func (s *Server) handleAPIMonitorsUnified(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/monitors/")
	if rest == "" { // collection
		s.handleAPIMonitorsCollection(w, r)
		return
	}
	s.handleAPIMonitorItem(w, r)
}

// API: reorder monitors within and across groups.
// Accepts JSON only as { groups: [{group_id: number, order: ["id1","id2", ...]}, ...] }
func (s *Server) handleAPIMonitorsReorder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.apiDebug {
		s.logger.Printf("[API DEBUG] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	}

	if !s.ensureAuthAndCSRF(w, r) {
		return
	}
	var multi struct {
		Groups []struct {
			GroupID int      `json:"group_id"`
			Order   []string `json:"order"`
		} `json:"groups"`
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &multi); err == nil && len(multi.Groups) > 0 {
		// Build a map from monitor ID to its new group ID and order
		type placement struct {
			gid   int
			order int
		}
		pos := make(map[string]placement, 64)
		for _, g := range multi.Groups {
			for i, id := range g.Order {
				pos[id] = placement{gid: g.GroupID, order: i + 1}
			}
		}
		snapshots := s.manager.List()
		for _, snap := range snapshots {
			if p, ok := pos[snap.Config.ID]; ok {
				cfg := snap.Config
				cfg.GroupID = p.gid
				cfg.Group = s.getGroupName(p.gid)
				cfg.Order = p.order
				if _, err := s.manager.UpdateMonitor(cfg); err != nil {
					s.logger.Printf("reorder monitor %s: %v", cfg.ID, err)
				}
			}
		}
		if err := s.saveConfig(); err != nil {
			s.logger.Printf("persist after api reorder: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Error(w, "invalid json", http.StatusBadRequest)
}

// API: list/create monitors (Collection)
func (s *Server) handleAPIMonitorsCollection(w http.ResponseWriter, r *http.Request) {
	if s.apiDebug {
		s.logger.Printf("[API DEBUG] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	}
	switch r.Method {
	case http.MethodGet:
		snapshots := s.manager.List()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(snapshots); err != nil {
			s.logger.Printf("encode monitors list: %v", err)
		}
	case http.MethodPost:
		if !s.ensureAuthAndCSRF(w, r) {
			return
		}
		var req monitorRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		cfg, err := req.toConfig("")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// If no order specified or order is 0, calculate next order for the group
		if cfg.Order <= 0 {
			cfg.Order = s.getNextOrderForGroup(cfg.GroupID)
		}
		// Resolve NotifyURL from selected notification, or clear if none selected
		if cfg.NotificationID > 0 {
			for _, n := range s.notifications {
				if n.ID == cfg.NotificationID {
					cfg.NotifyURL = strings.TrimSpace(n.URL)
					break
				}
			}
		} else {
			cfg.NotifyURL = ""
		}
		monitorCfg, err := s.manager.AddMonitor(cfg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.persistMonitors(); err != nil {
			s.logger.Printf("persist monitors after api create: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(monitorCfg)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// API: get/update/delete a single monitor (Item)
func (s *Server) handleAPIMonitorItem(w http.ResponseWriter, r *http.Request) {
	if s.apiDebug {
		s.logger.Printf("[API DEBUG] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/monitors/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		snapshot, err := s.manager.GetSnapshot(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		apiSnapshot := convertSnapshotToAPI(snapshot)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(apiSnapshot)
	case http.MethodPut:
		if !s.ensureAuthAndCSRF(w, r) {
			return
		}
		var req monitorRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		cfg, err := req.toConfig(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if cfg.NotificationID > 0 {
			for _, n := range s.notifications {
				if n.ID == cfg.NotificationID {
					cfg.NotifyURL = strings.TrimSpace(n.URL)
					break
				}
			}
		} else {
			cfg.NotifyURL = ""
		}
		monitorCfg, err := s.manager.UpdateMonitor(cfg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.persistMonitors(); err != nil {
			s.logger.Printf("persist monitors after api update: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(monitorCfg)
	case http.MethodDelete:
		if !s.ensureAuthAndCSRF(w, r) {
			return
		}
		if err := s.manager.RemoveMonitor(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if err := s.persistMonitors(); err != nil {
			s.logger.Printf("persist monitors after api delete: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ==== API: Status =============================================================

// handleAPIStatus mirrors handleStatusJSON but under /api/status as per REST API prefix requirement.
func (s *Server) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.apiDebug {
		s.logger.Printf("[API DEBUG] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	}
	snapshots := s.manager.List()
	response := make([]map[string]any, 0, len(snapshots))
	for _, snap := range snapshots {
		// Limit history to the last 'historyPreview' entries
		start := 0
		if len(snap.History) > historyPreview {
			start = len(snap.History) - historyPreview
		}
		histSlice := snap.History[start:]
		history := make([]map[string]any, 0, len(histSlice))
		for _, h := range histSlice {
			history = append(history, map[string]any{
				"timestamp":  h.Timestamp,
				"success":    h.Success,
				"latency_ms": h.Latency.Seconds() * 1000,
				"message":    h.Message,
			})
		}
		response = append(response, map[string]any{
			"id":               snap.Config.ID,
			"name":             snap.Config.Name,
			"type":             snap.Config.Type,
			"target":           snap.Config.Target,
			"master_id":        snap.Config.MasterID,
			"enabled":          snap.Config.Enabled,
			"group_id":         snap.Config.GroupID,
			"group":            s.getGroupName(snap.Config.GroupID),
			"interval_seconds": int(snap.Config.Interval.Seconds()),
			"timeout_seconds":  int(snap.Config.Timeout.Seconds()),
			"status":           snap.Status,
			"last_checked":     snap.LastChecked,
			"last_latency_ms":  snap.LastLatency.Seconds() * 1000,
			"last_message":     snap.LastMessage,
			"last_change":      snap.LastChange,
			"history":          history,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Printf("encode api status json: %v", err)
	}
}

// handleAPIMemory returns memory usage statistics
func (s *Server) handleAPIMemory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.apiDebug {
		s.logger.Printf("[API DEBUG] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	}

	memoryUsage := s.manager.GetMemoryUsage()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(memoryUsage)
}

// ==== API: Notifications ======================================================

func (s *Server) handleAPINotificationsUnified(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/notifications/")
	if rest == "" { // collection
		s.handleAPINotificationsCollection(w, r)
		return
	}
	if strings.HasSuffix(rest, "/test") {
		s.handleAPINotificationTest(w, r)
		return
	}
	s.handleAPINotificationItem(w, r)
}

// GET /api/notifications, POST /api/notifications
func (s *Server) handleAPINotificationsCollection(w http.ResponseWriter, r *http.Request) {
	if s.apiDebug {
		s.logger.Printf("[API DEBUG] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	}
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.notifications)
	case http.MethodPost:
		// First check authentication
		if !s.ensureAuth(w, r) {
			return
		}

		var body struct {
			Name, URL string
			CSRFToken string `json:"csrf_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}

		// Validate CSRF token from JSON body
		if !s.validateCSRFTokenFromJSON(r, body.CSRFToken) {
			http.Error(w, "CSRF token validation failed", http.StatusForbidden)
			return
		}

		name := strings.TrimSpace(body.Name)
		urlStr := normalizeShoutrrrURL(strings.TrimSpace(body.URL))
		if name == "" || urlStr == "" {
			http.Error(w, "name and url are required", http.StatusBadRequest)
			return
		}

		var id int

		// If database is configured, create notification in database first to get proper ID
		if s.databaseConfig != nil && s.configDB != nil {
			notificationData := database.NotificationData{
				Name: name,
				URL:  urlStr,
			}
			savedNotification, dbErr := s.configDB.SaveNotification(notificationData)
			if dbErr != nil {
				s.logger.Printf("Failed to save notification to database: %v", dbErr)
				http.Error(w, "database error", http.StatusInternalServerError)
				return
			}
			id = savedNotification.ID
		} else {
			// Fallback to server-generated ID for file-only mode
			id = s.newNotificationID()
		}

		n := config.NotificationConfig{ID: id, Name: name, URL: urlStr}
		s.notifications = append(s.notifications, n)
		if err := s.saveConfig(); err != nil {
			s.logger.Printf("persist after api notification create: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(n)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAPINotificationItem(w http.ResponseWriter, r *http.Request) {
	if s.apiDebug {
		s.logger.Printf("[API DEBUG] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/notifications/")
	if idStr == "" {
		http.NotFound(w, r)
		return
	}
	nid, err := strconv.Atoi(idStr)
	if err != nil || nid <= 0 {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		for _, n := range s.notifications {
			if n.ID == nid {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(n)
				return
			}
		}
		http.NotFound(w, r)
	case http.MethodPut:
		// First check authentication
		if !s.ensureAuth(w, r) {
			return
		}

		var body struct {
			Name, URL string
			CSRFToken string `json:"csrf_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}

		// Validate CSRF token from JSON body
		if !s.validateCSRFTokenFromJSON(r, body.CSRFToken) {
			http.Error(w, "CSRF token validation failed", http.StatusForbidden)
			return
		}
		for i := range s.notifications {
			if s.notifications[i].ID == nid {
				s.notifications[i].Name = strings.TrimSpace(body.Name)
				s.notifications[i].URL = normalizeShoutrrrURL(strings.TrimSpace(body.URL))
				if err := s.saveConfig(); err != nil {
					s.logger.Printf("persist after api notification update: %v", err)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(s.notifications[i])
				return
			}
		}
		http.NotFound(w, r)
	case http.MethodDelete:
		if !s.ensureAuthAndCSRF(w, r) {
			return
		}
		idx := -1
		for i, n := range s.notifications {
			if n.ID == nid {
				idx = i
				break
			}
		}
		if idx == -1 {
			http.NotFound(w, r)
			return
		}
		s.notifications = append(s.notifications[:idx], s.notifications[idx+1:]...)
		cfgs := s.manager.GetAllConfigs()
		changed := false
		for i := range cfgs {
			if cfgs[i].NotificationID == nid {
				cfgs[i].NotificationID = 0
				if _, err := s.manager.UpdateMonitor(cfgs[i]); err != nil {
					s.logger.Printf("clear notification ref for monitor %s: %v", cfgs[i].ID, err)
				}
				changed = true
			}
		}
		if changed {
			if err := s.saveConfig(); err != nil {
				s.logger.Printf("persist after api notification delete refs: %v", err)
			}
		}
		if err := s.saveConfig(); err != nil {
			s.logger.Printf("persist after api notification delete: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// POST /api/notifications/{id}/test
// Sends a test notification to the configured URL for the given notification ID.
func (s *Server) handleAPINotificationTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.apiDebug {
		s.logger.Printf("[API DEBUG] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	}
	if !s.ensureAuthAndCSRF(w, r) {
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/notifications/")
	// Expect format: {id}/test
	parts := strings.Split(strings.TrimSuffix(idStr, "/"), "/")
	if len(parts) < 2 || parts[1] != "test" {
		http.NotFound(w, r)
		return
	}
	nid, err := strconv.Atoi(parts[0])
	if err != nil || nid <= 0 {
		http.NotFound(w, r)
		return
	}
	// Find the notification config
	var urlStr, name string
	for _, n := range s.notifications {
		if n.ID == nid {
			urlStr = strings.TrimSpace(n.URL)
			name = n.Name
			break
		}
	}
	if urlStr == "" {
		http.Error(w, "notification not found", http.StatusNotFound)
		return
	}
	// Build a test notification payload
	msg := monitor.Notification{
		MonitorID:   "test",
		MonitorName: "Upturtle",
		Target:      "",
		Type:        monitor.TypeHTTP,
		Status:      monitor.StatusUp,
		Message:     "This is a test notification for '" + name + "'",
		NotifyURL:   urlStr,
	}
	n := notifier.NewShoutrrrNotifier()
	if err := n.Notify(msg); err != nil {
		s.logger.Printf("test notification error for id %d: %v", nid, err)
		http.Error(w, "failed to send test notification", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ==== API: Groups =============================================================

func (s *Server) handleAPIGroupsUnified(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/groups/")
	if rest == "" { // collection
		s.handleAPIGroupsCollection(w, r)
		return
	}
	s.handleAPIGroupItem(w, r)
}

// GET /api/groups (list), POST /api/groups (create)
func (s *Server) handleAPIGroupsCollection(w http.ResponseWriter, r *http.Request) {
	if s.apiDebug {
		s.logger.Printf("[API DEBUG] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	}
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.groups)
	case http.MethodPost:
		if !s.ensureAuthAndCSRF(w, r) {
			return
		}
		var body struct{ Name string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		name := strings.TrimSpace(body.Name)
		if name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		for _, g := range s.groups {
			if g.Name == name {
				http.Error(w, "group exists", http.StatusConflict)
				return
			}
		}
		// compute next order as max(Order)+1
		nextOrder := 1
		for _, g := range s.groups {
			if g.Order >= nextOrder {
				nextOrder = g.Order + 1
			}
		}

		var gid int

		// If database is configured, create group in database first to get proper ID
		if s.databaseConfig != nil && s.configDB != nil {
			groupData := database.GroupData{
				Name:  name,
				Order: nextOrder,
			}
			savedGroup, dbErr := s.configDB.SaveGroup(groupData)
			if dbErr != nil {
				s.logger.Printf("Failed to save group to database: %v", dbErr)
				http.Error(w, "database error", http.StatusInternalServerError)
				return
			}
			gid = savedGroup.ID
		} else {
			// Fallback to server-generated ID for file-only mode
			if s.nextGroupID <= 0 {
				s.nextGroupID = 1
			}
			gid = s.nextGroupID
			s.nextGroupID++
		}

		s.groups = append(s.groups, config.GroupConfig{ID: gid, Name: name, Order: nextOrder})
		s.normalizeAndSortGroups()

		// Save config (will update database again in DB mode, but with correct ID)
		if err := s.saveConfig(); err != nil {
			s.logger.Printf("persist api group create: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": gid, "name": name, "order": nextOrder})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// PUT/DELETE /api/groups/{id}
func (s *Server) handleAPIGroupItem(w http.ResponseWriter, r *http.Request) {
	if s.apiDebug {
		s.logger.Printf("[API DEBUG] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/groups/")
	if idStr == "" {
		http.NotFound(w, r)
		return
	}
	gid, err := strconv.Atoi(idStr)
	if err != nil || gid <= 0 {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPut:
		if !s.ensureAuthAndCSRF(w, r) {
			return
		}
		var body struct {
			Name string
			Move string
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		idx := -1
		for i, g := range s.groups {
			if g.ID == gid {
				idx = i
				break
			}
		}
		if idx == -1 {
			http.NotFound(w, r)
			return
		}
		mv := strings.ToLower(strings.TrimSpace(body.Move))
		if mv == "up" || mv == "down" {
			// find neighbor by Order and swap Order values
			s.normalizeAndSortGroups()
			// refresh idx post-sort
			idx = -1
			for i, g := range s.groups {
				if g.ID == gid {
					idx = i
					break
				}
			}
			if idx == -1 {
				http.NotFound(w, r)
				return
			}
			if mv == "up" && idx > 0 {
				s.groups[idx].Order, s.groups[idx-1].Order = s.groups[idx-1].Order, s.groups[idx].Order
			}
			if mv == "down" && idx < len(s.groups)-1 {
				s.groups[idx].Order, s.groups[idx+1].Order = s.groups[idx+1].Order, s.groups[idx].Order
			}
			s.normalizeAndSortGroups()
			if err := s.saveConfig(); err != nil {
				s.logger.Printf("persist api group move: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		newName := strings.TrimSpace(body.Name)
		if newName != "" && newName != s.groups[idx].Name {
			// rename
			s.groups[idx].Name = newName
			snaps := s.manager.List()
			for _, snap := range snaps {
				if snap.Config.GroupID == gid {
					cfg := snap.Config
					cfg.Group = newName
					if _, err := s.manager.UpdateMonitor(cfg); err != nil {
						s.logger.Printf("rename group for monitor %s: %v", cfg.ID, err)
					}
				}
			}
			s.normalizeAndSortGroups()
			if err := s.saveConfig(); err != nil {
				s.logger.Printf("persist api group rename: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "nothing to update", http.StatusBadRequest)
	case http.MethodDelete:
		if !s.ensureAuthAndCSRF(w, r) {
			return
		}
		q := r.URL.Query().Get("delete_monitors")
		deleteMon := q == "1" || strings.ToLower(q) == "true" || q == "yes"
		idx := -1
		for i, g := range s.groups {
			if g.ID == gid {
				idx = i
				break
			}
		}
		if idx == -1 {
			http.NotFound(w, r)
			return
		}
		s.groups = append(s.groups[:idx], s.groups[idx+1:]...)
		s.normalizeAndSortGroups()
		snaps := s.manager.List()
		for _, snap := range snaps {
			if snap.Config.GroupID != gid {
				continue
			}
			if deleteMon {
				_ = s.manager.RemoveMonitor(snap.Config.ID)
			} else {
				cfg := snap.Config
				cfg.Group = ""
				cfg.GroupID = 0
				_, _ = s.manager.UpdateMonitor(cfg)
			}
		}
		if err := s.saveConfig(); err != nil {
			s.logger.Printf("persist api group delete: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ==== Routing & Middleware ====================================================

func (s *Server) routes() {
	// Always allow status endpoints
	s.mux.HandleFunc("/", s.handleStatus)
	s.mux.HandleFunc("/api/status", s.handleAPIStatus)
	s.mux.HandleFunc("/api/memory", s.handleAPIMemory)

	// Static assets (e.g., logos) served from embedded FS with disk fallback and logo.png placeholder
	s.mux.Handle("/static/", http.StripPrefix("/static/", newStaticHandler()))

	// Installation endpoint
	s.mux.HandleFunc("/install", s.handleInstall)

	// Login/logout endpoints
	s.mux.HandleFunc("/login", s.handleLogin)
	s.mux.HandleFunc("/logout", s.handleLogout)

	// Admin pages (render only). Actions now go through REST API.
	// Monitors page is the main /admin (rendered by handleAdmin)
	s.mux.HandleFunc("/admin", s.ensureInstalled(s.handleAdmin))
	// Notifications page (GET only)
	s.mux.HandleFunc("/admin/notifications", s.ensureInstalled(s.handleAdminNotifications))
	s.mux.HandleFunc("/admin/notifications/", s.ensureInstalled(s.handleAdminNotifications))
	// Settings
	s.mux.HandleFunc("/admin/settings", s.ensureInstalled(s.handleAdminSettings))
	// Group actions go via REST API now; monitor reorder moved to /api/monitors/reorder

	// API endpoints (one handler per resource), support with and without trailing slash
	s.mux.HandleFunc("/api/monitors", s.ensureInstalled(s.handleAPIMonitorsUnified))
	s.mux.HandleFunc("/api/monitors/", s.ensureInstalled(s.handleAPIMonitorsUnified))
	s.mux.HandleFunc("/api/monitors/reorder", s.ensureInstalled(s.handleAPIMonitorsReorder))
	s.mux.HandleFunc("/api/notifications", s.ensureInstalled(s.handleAPINotificationsUnified))
	s.mux.HandleFunc("/api/notifications/", s.ensureInstalled(s.handleAPINotificationsUnified))
	s.mux.HandleFunc("/api/groups", s.ensureInstalled(s.handleAPIGroupsUnified))
	s.mux.HandleFunc("/api/groups/", s.ensureInstalled(s.handleAPIGroupsUnified))
	s.mux.HandleFunc("/api/settings", s.ensureInstalled(s.handleAPISettings))
	s.mux.HandleFunc("/api/history/", s.ensureInstalled(s.handleAPIHistory))
}

// ensureInstalled is a simple middleware wrapper that can enforce installation
// preconditions for specific handlers. Global enforcement also happens in
// ServeHTTP, but routes are wrapped with this for clarity and future extension.
func (s *Server) ensureInstalled(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.installRequired && r.URL.Path != "/install" {
			http.Redirect(w, r, "/install", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (s *Server) normalizeAndSortGroups() {
	if len(s.groups) == 0 {
		return
	}
	// Start fresh: assume all groups have a valid, explicit Order in config.
	sort.SliceStable(s.groups, func(i, j int) bool {
		if s.groups[i].Order == s.groups[j].Order {
			return s.groups[i].Name < s.groups[j].Name
		}
		oi := s.groups[i].Order
		oj := s.groups[j].Order
		return oi < oj
	})
}

// ---- Notifications management ----
// handleAdminNotifications lists notifications (GET) and creates a new one (POST)
func (s *Server) handleAdminNotifications(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		data := struct {
			BasePageData
			Notifications []config.NotificationConfig
			Error         string
			Success       string
		}{
			BasePageData: BasePageData{
				Title:             "Notifications",
				ContentTemplate:   "notifications.content",
				CSRFToken:         s.getCSRFToken(r),
				ShowMemoryDisplay: s.showMemoryDisplay,
			},
			Notifications: append([]config.NotificationConfig(nil), s.notifications...),
			Error:         r.URL.Query().Get("error"),
			Success:       r.URL.Query().Get("success"),
		}
		if err := s.templates.ExecuteTemplate(w, "notifications.gohtml", data); err != nil {
			s.logger.Printf("notifications template error: %v", err)
			http.Error(w, "template error", http.StatusInternalServerError)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---- Notification helpers & actions ----

// newNotificationID returns the next incremental notification ID
func (s *Server) newNotificationID() int {
	if s.nextNotificationID <= 0 {
		s.nextNotificationID = 1
	}
	id := s.nextNotificationID
	s.nextNotificationID++
	return id
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Apply security headers to all responses
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

	// If installation is required, redirect all requests to /install
	// until credentials are configured, except when already on /install.
	if s.installRequired && r.URL.Path != "/install" && !strings.HasPrefix(r.URL.Path, "/static/") {
		http.Redirect(w, r, "/install", http.StatusSeeOther)
		return
	}

	// If admin credentials are configured, enforce login globally
	if s.adminUser != "" && s.adminPassword != "" {
		isPublic := s.isPublicPath(r.URL.Path)
		isAuth := s.isAuthenticated(r)
		s.authDebugf("Auth middleware: path='%s', isPublic=%t, isAuthenticated=%t", r.URL.Path, isPublic, isAuth)

		if !isPublic && !isAuth {
			s.authDebugf("Redirecting unauthenticated request to /login")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
	}

	s.mux.ServeHTTP(w, r)
}

// isPublicPath returns true for endpoints that do not require login.
func (s *Server) isPublicPath(p string) bool {
	// Allow login, install (only while install is required), and all assets under /static/
	if p == "/login" || (p == "/install" && s.installRequired) || strings.HasPrefix(p, "/static/") {
		return true
	}
	return false
}

// ==== Auth & Sessions =========================================================

// handleLogin renders and processes the login form.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.adminUser == "" || s.adminPassword == "" {
		// No credentials configured; nothing to log in to.
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if s.isAuthenticated(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.authDebugf("Login GET request from %s, User-Agent: %s", r.RemoteAddr, r.UserAgent())
		csrfToken := s.getCSRFToken(r)
		s.authDebugf("Generated CSRF token for login form: %s...", csrfToken[:10])

		data := struct {
			BasePageData
			Error string
		}{
			BasePageData: BasePageData{
				Title:           "Login",
				ContentTemplate: "login.content",
				HideHeader:      true,
				CSRFToken:       csrfToken,
			},
			Error: r.URL.Query().Get("error"),
		}

		if errorMsg := r.URL.Query().Get("error"); errorMsg != "" {
			s.authDebugf("Login form showing error: %s", errorMsg)
		}

		if err := s.templates.ExecuteTemplate(w, "login.gohtml", data); err != nil {
			s.logger.Printf("login template error: %v", err)
			http.Error(w, "template error", http.StatusInternalServerError)
		}
	case http.MethodPost:
		// Validate CSRF token for login form
		s.authDebugf("Login POST attempt from %s, User-Agent: %s", r.RemoteAddr, r.UserAgent())
		if !s.validateCSRFToken(r) {
			s.authDebugf("Login failed: CSRF token validation failed for %s", r.RemoteAddr)
			http.Redirect(w, r, "/login?error="+url.QueryEscape("CSRF token validation failed"), http.StatusSeeOther)
			return
		}
		if err := r.ParseForm(); err != nil {
			s.authDebugf("Login failed: form parsing error: %v", err)
			http.Redirect(w, r, "/login?error="+url.QueryEscape("invalid form"), http.StatusSeeOther)
			return
		}
		user := strings.TrimSpace(r.FormValue("username"))
		pass := r.FormValue("password")
		s.authDebugf("Login attempt: username='%s', password_length=%d", user, len(pass))
		s.authDebugf("Expected username='%s', admin_password_set=%t", s.adminUser, s.adminPassword != "")

		// Check username match
		usernameMatch := user == s.adminUser
		s.authDebugf("Username match: %t", usernameMatch)

		// Check password
		passwordValid := s.verifyPassword(pass)
		s.authDebugf("Password valid: %t", passwordValid)

		if usernameMatch && passwordValid {
			s.authDebugf("Login successful for user '%s', creating session", user)
			if err := s.createSession(w, r); err != nil {
				s.logger.Printf("[ERROR] create session error: %v", err)
				http.Redirect(w, r, "/login?error="+url.QueryEscape("internal error"), http.StatusSeeOther)
				return
			}
			s.authDebugf("Session created successfully, redirecting to /")
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		s.authDebugf("Login failed: invalid credentials for user '%s'", user)
		http.Redirect(w, r, "/login?error="+url.QueryEscape("invalid credentials"), http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleLogout clears the session and redirects to login.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.destroySession(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// isAuthenticated checks for a valid session cookie.
func (s *Server) isAuthenticated(r *http.Request) bool {
	if s.adminUser == "" || s.adminPassword == "" {
		s.authDebugf("No admin credentials configured, allowing access")
		return true
	}
	c, err := r.Cookie("upturtle_session")
	if err != nil {
		s.authDebugf("No session cookie found: %v", err)
		return false
	}
	if c.Value == "" {
		s.authDebugf("Empty session cookie value")
		return false
	}
	id := c.Value
	s.authDebugf("Checking session: ID='%s'...", id[:8])
	if exp, ok := s.sessions[id]; ok {
		now := time.Now()
		if now.Before(exp) {
			s.authDebugf("Session valid: expires in %v", exp.Sub(now))
			return true
		} else {
			s.authDebugf("Session expired: was valid until %s", exp.Format(time.RFC3339))
			// Clean up expired session
			delete(s.sessions, id)
			delete(s.csrfTokens, id)
		}
	} else {
		s.authDebugf("Session not found in server memory")
	}
	return false
}

// ensureAuth protects API routes. If admin credentials are configured, accept either
// a valid logged-in session OR valid HTTP Basic credentials.
func (s *Server) ensureAuth(w http.ResponseWriter, r *http.Request) bool {
	if s.adminUser == "" || s.adminPassword == "" {
		return true
	}
	// Prefer session cookie to avoid browser basic-auth prompts
	if c, err := r.Cookie("upturtle_session"); err == nil && c.Value != "" {
		if exp, ok := s.sessions[c.Value]; ok && time.Now().Before(exp) {
			return true
		}
	}
	// Fallback to HTTP Basic
	if user, pass, ok := r.BasicAuth(); ok {
		if user == s.adminUser && s.verifyPassword(pass) {
			return true
		}
	}
	w.Header().Set("WWW-Authenticate", "Basic realm=upturtle")
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

// ensureAuthAndCSRF protects API routes with both authentication and CSRF validation
func (s *Server) ensureAuthAndCSRF(w http.ResponseWriter, r *http.Request) bool {
	// First check authentication
	if !s.ensureAuth(w, r) {
		return false
	}

	// Skip CSRF check for GET requests (they should be safe)
	if r.Method == http.MethodGet {
		return true
	}

	// Skip CSRF check for HTTP Basic Auth (API clients)
	if _, _, ok := r.BasicAuth(); ok {
		return true
	}

	// For session-based requests, validate CSRF token
	if !s.validateCSRFToken(r) {
		http.Error(w, "CSRF token validation failed", http.StatusForbidden)
		return false
	}

	return true
}

// verifyPassword compares a raw password against the stored bcrypt hash
func (s *Server) verifyPassword(password string) bool {
	if s.adminPassword == "" {
		s.authDebugf("Password verification failed: no admin password configured")
		return false
	}

	s.authDebugf("Verifying password: provided_length=%d, stored_hash_length=%d", len(password), len(s.adminPassword))

	// Check if the stored password looks like a bcrypt hash
	if !strings.HasPrefix(s.adminPassword, "$2") {
		s.authDebugf("Warning: stored admin password doesn't look like a bcrypt hash (should start with $2)")
	}

	err := bcrypt.CompareHashAndPassword([]byte(s.adminPassword), []byte(password))
	if err != nil {
		s.authDebugf("Password verification failed: %v", err)
		return false
	}

	s.authDebugf("Password verification successful")
	return true
}

// createSession creates a new session and sets a cookie.
func (s *Server) createSession(w http.ResponseWriter, r *http.Request) error {
	s.authDebugf("Creating session for %s, User-Agent: %s", r.RemoteAddr, r.UserAgent())
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		s.logger.Printf("[ERROR] Failed to generate session ID: %v", err)
		return err
	}
	id := hex.EncodeToString(b)
	// 24h session
	expiry := time.Now().Add(24 * time.Hour)
	s.sessions[id] = expiry
	s.authDebugf("Session created: ID='%s', expires=%s", id[:8]+"...", expiry.Format(time.RFC3339))

	// Clean up any temporary CSRF token for this client
	tempKey := "temp_" + r.RemoteAddr + "_" + r.UserAgent()
	delete(s.csrfTokens, tempKey)
	s.authDebugf("Cleaned up temporary CSRF token: '%s'", tempKey)

	// Check if request is over HTTPS
	isHTTPS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	s.authDebugf("Request is HTTPS: %t (TLS: %t, X-Forwarded-Proto: %s)", isHTTPS, r.TLS != nil, r.Header.Get("X-Forwarded-Proto"))

	cookie := &http.Cookie{
		Name:     "upturtle_session",
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS,              // Only secure if actually HTTPS
		SameSite: http.SameSiteLaxMode, // Changed from Strict to Lax for better compatibility
		Expires:  expiry,
	}
	s.authDebugf("Setting cookie: Name=%s, Secure=%t, SameSite=%v, HttpOnly=%t", cookie.Name, cookie.Secure, cookie.SameSite, cookie.HttpOnly)
	http.SetCookie(w, cookie)
	s.authDebugf("Session cookie set successfully")
	return nil
}

func (s *Server) destroySession(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("upturtle_session")
	if err == nil && c.Value != "" {
		delete(s.sessions, c.Value)
		// Also remove CSRF token for this session
		delete(s.csrfTokens, c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "upturtle_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
}

// ==== CSRF Protection =========================================================

// generateCSRFToken creates a cryptographically secure CSRF token
func (s *Server) generateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		s.logger.Printf("CSRF token generation error: %v", err)
		// Fallback to less secure but still usable token
		return hex.EncodeToString([]byte(strconv.FormatInt(time.Now().UnixNano(), 36)))
	}
	return hex.EncodeToString(b)
}

// getCSRFToken returns the CSRF token for the current session, creating one if needed
// For requests without sessions (login/install), generates a temporary token
func (s *Server) getCSRFToken(r *http.Request) string {
	sessionID := s.getSessionID(r)
	s.authDebugf("Getting CSRF token: sessionID='%s', RemoteAddr='%s', UserAgent='%s'", sessionID, r.RemoteAddr, r.UserAgent())

	// For authenticated sessions, use session-based tokens
	if sessionID != "" {
		// Check if token already exists for this session
		if token, exists := s.csrfTokens[sessionID]; exists {
			s.authDebugf("Returning existing session CSRF token")
			return token
		}

		// Generate new token for this session
		token := s.generateCSRFToken()
		s.csrfTokens[sessionID] = token
		s.authDebugf("Generated new session CSRF token")
		return token
	}

	// For unauthenticated requests (login/install), generate a temporary token
	// Store it with a special key based on remote address and user agent
	// Special handling for Safari mobile which may have changing User-Agent strings
	userAgent := r.UserAgent()
	isSafariMobile := strings.Contains(userAgent, "Safari") && (strings.Contains(userAgent, "Mobile") || strings.Contains(userAgent, "iPhone") || strings.Contains(userAgent, "iPad"))

	var tempKey string
	if isSafariMobile {
		// For Safari mobile, use a simpler key that's less likely to change
		tempKey = "temp_safari_" + r.RemoteAddr
		s.authDebugf("Using Safari mobile CSRF key: '%s'", tempKey)
	} else {
		tempKey = "temp_" + r.RemoteAddr + "_" + userAgent
		s.authDebugf("Using standard CSRF key: '%s'", tempKey)
	}

	if token, exists := s.csrfTokens[tempKey]; exists {
		s.authDebugf("Returning existing temporary CSRF token")
		return token
	}

	token := s.generateCSRFToken()
	s.csrfTokens[tempKey] = token
	s.authDebugf("Generated new temporary CSRF token")
	return token
}

// getSessionID extracts the session ID from the request
func (s *Server) getSessionID(r *http.Request) string {
	cookie, err := r.Cookie("upturtle_session")
	if err != nil || cookie.Value == "" {
		return ""
	}
	return cookie.Value
}

// validateCSRFToken validates the CSRF token from the request
func (s *Server) validateCSRFToken(r *http.Request) bool {
	sessionID := s.getSessionID(r)
	s.authDebugf("CSRF validation: sessionID='%s', RemoteAddr='%s', UserAgent='%s'", sessionID, r.RemoteAddr, r.UserAgent())

	var expectedToken string
	var exists bool
	var tokenKey string

	// For authenticated sessions, use session-based tokens
	if sessionID != "" {
		tokenKey = sessionID
		expectedToken, exists = s.csrfTokens[sessionID]
		s.authDebugf("CSRF: Using session-based token, key='%s', exists=%t", tokenKey, exists)
	} else {
		// For unauthenticated requests (login/install), use temporary tokens
		// Special handling for Safari mobile
		userAgent := r.UserAgent()
		isSafariMobile := strings.Contains(userAgent, "Safari") && (strings.Contains(userAgent, "Mobile") || strings.Contains(userAgent, "iPhone") || strings.Contains(userAgent, "iPad"))

		if isSafariMobile {
			tokenKey = "temp_safari_" + r.RemoteAddr
		} else {
			tokenKey = "temp_" + r.RemoteAddr + "_" + userAgent
		}
		expectedToken, exists = s.csrfTokens[tokenKey]
		s.authDebugf("CSRF: Using temporary token (Safari mobile: %t), key='%s', exists=%t", isSafariMobile, tokenKey, exists)
	}

	if !exists {
		s.authDebugf("CSRF validation failed: no token found for key '%s'", tokenKey)
		s.authDebugf("CSRF: Available tokens: %d", len(s.csrfTokens))
		for k := range s.csrfTokens {
			s.authDebugf("CSRF: Available key: '%s'", k)
		}
		return false
	}

	// Get token from request (try header first, then form)
	var providedToken string
	if headerToken := r.Header.Get("X-CSRF-Token"); headerToken != "" {
		providedToken = headerToken
		tokenPreview := providedToken
		if len(tokenPreview) > 10 {
			tokenPreview = tokenPreview[:10] + "..."
		}
		s.authDebugf("CSRF: Got token from header: '%s'", tokenPreview)
	} else if err := r.ParseForm(); err == nil {
		providedToken = r.FormValue("csrf_token")
		tokenPreview := providedToken
		if len(tokenPreview) > 10 {
			tokenPreview = tokenPreview[:10] + "..."
		}
		s.authDebugf("CSRF: Got token from form: '%s'", tokenPreview)
	} else {
		s.authDebugf("CSRF: Failed to parse form: %v", err)
	}

	if providedToken == "" {
		s.authDebugf("CSRF validation failed: no token provided in request")
		return false
	}

	// Constant-time comparison to prevent timing attacks
	valid := len(expectedToken) == len(providedToken) && expectedToken == providedToken
	s.authDebugf("CSRF validation result: %t (expected length: %d, provided length: %d)", valid, len(expectedToken), len(providedToken))
	return valid
}

// validateCSRFTokenFromJSON validates CSRF token from a JSON body
func (s *Server) validateCSRFTokenFromJSON(r *http.Request, jsonToken string) bool {
	sessionID := s.getSessionID(r)

	var expectedToken string
	var exists bool

	// For authenticated sessions, use session-based tokens
	if sessionID != "" {
		expectedToken, exists = s.csrfTokens[sessionID]
	} else {
		// For unauthenticated requests (login/install), use temporary tokens
		tempKey := "temp_" + r.RemoteAddr + "_" + r.UserAgent()
		expectedToken, exists = s.csrfTokens[tempKey]
	}

	if !exists || jsonToken == "" {
		return false
	}

	// Constant-time comparison to prevent timing attacks
	return len(expectedToken) == len(jsonToken) &&
		expectedToken == jsonToken
}

// startSessionCleanup starts a background goroutine to periodically clean up expired sessions and CSRF tokens
func (s *Server) startSessionCleanup() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour) // Clean up every hour
		defer ticker.Stop()

		for range ticker.C {
			s.cleanupExpiredSessions()
		}
	}()
}

// cleanupExpiredSessions removes expired sessions and their associated CSRF tokens
func (s *Server) cleanupExpiredSessions() {
	now := time.Now()
	expiredSessions := make([]string, 0)

	// Find expired sessions
	for sessionID, expiry := range s.sessions {
		if now.After(expiry) {
			expiredSessions = append(expiredSessions, sessionID)
		}
	}

	// Remove expired sessions and their CSRF tokens
	for _, sessionID := range expiredSessions {
		delete(s.sessions, sessionID)
		delete(s.csrfTokens, sessionID)
	}

	// Also clean up old temporary CSRF tokens (older than 24 hours)
	tempTokensRemoved := 0
	for key := range s.csrfTokens {
		if strings.HasPrefix(key, "temp_") {
			// Remove all temp tokens during cleanup (they should be short-lived anyway)
			delete(s.csrfTokens, key)
			tempTokensRemoved++
		}
	}

	if len(expiredSessions) > 0 || tempTokensRemoved > 0 {
		s.logger.Printf("Cleaned up %d expired sessions and %d temporary CSRF tokens", len(expiredSessions), tempTokensRemoved)
	}
}

// ==== Status Page =============================================================

// handleStatus serves the main status page
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	data := s.buildStatusData()
	if err := s.templates.ExecuteTemplate(w, "status.gohtml", data); err != nil {
		s.logger.Printf("status template error: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// ==== API: History ============================================================

// handleAPIHistory serves monitor history data
func (s *Server) handleAPIHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.ensureAuth(w, r) {
		return
	}

	if s.apiDebug {
		s.logger.Printf("[API DEBUG] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	}

	// Parse monitor ID from path: /api/history/{id}
	id := strings.TrimPrefix(r.URL.Path, "/api/history/")
	if id == "" {
		http.Error(w, "monitor ID required", http.StatusBadRequest)
		return
	}

	snapshot, err := s.manager.GetSnapshot(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Convert history to API format
	apiHistory := make([]APICheckResult, len(snapshot.History))
	for i, result := range snapshot.History {
		apiHistory[i] = convertCheckResultToAPI(result)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(apiHistory)
}

func (s *Server) buildStatusData() StatusPageData {
	snapshots := s.manager.List()
	// Build a quick lookup of monitor status by ID (for master dependency)
	statusByID := make(map[string]monitor.Status, len(snapshots))
	for _, snap := range snapshots {
		statusByID[snap.Config.ID] = snap.Status
	}
	// group snapshots by group ID
	grouped := map[int][]StatusMonitorView{}
	for _, snap := range snapshots {
		gid := snap.Config.GroupID
		v := toStatusMonitorView(snap)
		// Resolve group name from ID for display
		v.Group = s.getGroupName(gid)
		if v.MasterID != "" {
			if st, ok := statusByID[v.MasterID]; ok {
				v.MasterDown = (st == monitor.StatusDown)
			}
		}
		grouped[gid] = append(grouped[gid], v)
	}
	// determine group order by configured order, include any missing IDs
	orderedIDs := make([]int, 0, len(s.groups))
	seen := map[int]bool{}
	for _, gg := range s.groups {
		orderedIDs = append(orderedIDs, gg.ID)
		seen[gg.ID] = true
	}
	for gid := range grouped {
		if !seen[gid] {
			orderedIDs = append(orderedIDs, gid)
		}
	}
	// build views with monitor order
	views := make([]StatusGroupView, 0, len(orderedIDs))
	for _, gid := range orderedIDs {
		mons := grouped[gid]
		sort.Slice(mons, func(i, j int) bool {
			if mons[i].Order == mons[j].Order {
				return mons[i].Name < mons[j].Name
			}
			return mons[i].Order < mons[j].Order
		})
		views = append(views, StatusGroupView{Name: s.getGroupName(gid), Monitors: mons})
	}
	return StatusPageData{
		BasePageData: BasePageData{
			Title:             "Service Status",
			RefreshSeconds:    0,
			ContentTemplate:   "status.content",
			DatabaseEnabled:   s.manager.HasDatabaseIntegration(),
			DatabaseHealthy:   s.manager.IsDatabaseHealthy(),
			DatabaseError:     s.manager.GetDatabaseError(),
			ShowMemoryDisplay: s.showMemoryDisplay,
		},
		Groups: views,
	}
}

type monitorRequest struct {
	Name           string `json:"name"`
	Type           string `json:"type"`
	Target         string `json:"target"`
	Interval       int    `json:"interval_seconds"`
	Timeout        int    `json:"timeout_seconds"`
	NotificationID int    `json:"notification_id"`
	Enabled        *bool  `json:"enabled"`
	GroupID        int    `json:"group_id"`
	Group          string `json:"group"`
	Order          int    `json:"order"`
	MasterID       string `json:"master_id"`
	FailThreshold  int    `json:"fail_threshold"`
	CertValidation string `json:"cert_validation"`
}

func (m monitorRequest) toConfig(id string) (monitor.MonitorConfig, error) {
	target := strings.TrimSpace(m.Target)
	monitorType := monitor.Type(strings.TrimSpace(m.Type))

	cfg := monitor.MonitorConfig{
		ID:             id,
		Name:           strings.TrimSpace(m.Name),
		Type:           monitorType,
		Target:         target,
		NotificationID: m.NotificationID,
		Enabled:        true,
		GroupID:        m.GroupID,
		Group:          strings.TrimSpace(m.Group),
		Order:          m.Order,
	}
	if cfg.Type == "" {
		cfg.Type = monitor.TypeHTTP
	}
	if m.Interval <= 0 {
		m.Interval = 30
	}
	if m.Timeout <= 0 {
		m.Timeout = 10
	}
	cfg.Interval = time.Duration(m.Interval) * time.Second
	cfg.Timeout = time.Duration(m.Timeout) * time.Second
	if m.Enabled != nil {
		cfg.Enabled = *m.Enabled
	}
	cfg.MasterID = strings.TrimSpace(m.MasterID)
	if m.FailThreshold > 0 {
		cfg.FailThreshold = m.FailThreshold
	}
	// Set certificate validation mode
	certValidation := strings.TrimSpace(m.CertValidation)
	if certValidation == "" {
		certValidation = "full" // default to full validation
	}
	cfg.CertValidation = monitor.CertValidationMode(certValidation)
	// If NotificationID provided, do not attempt to override here; resolution happens in API handlers
	if cfg.Timeout > cfg.Interval {
		cfg.Timeout = cfg.Interval
	}
	return cfg, nil
}

// BasePageData contains shared fields between page templates.
type BasePageData struct {
	Title           string
	RefreshSeconds  int
	ContentTemplate string
	// When true, the main header bar is hidden (used for focused pages like install/login)
	HideHeader bool
	// CSRF token for form protection
	CSRFToken string
	// Database status information
	DatabaseEnabled bool
	DatabaseHealthy bool
	DatabaseError   string
	// UI settings
	ShowMemoryDisplay bool
}

// StatusGroupView is used by the public status page
type StatusGroupView struct {
	Name     string
	Monitors []StatusMonitorView
}

// AdminGroupView is used by the admin page
type AdminGroupView struct {
	ID       int
	Name     string
	Monitors []AdminMonitorView
}

// StatusPageData drives the public status template.
type StatusPageData struct {
	BasePageData
	// Groups is the grouped view for status rendering
	Groups []StatusGroupView
}

// AdminPageData drives the administrative template.
type AdminPageData struct {
	BasePageData
	// Groups is the grouped view for admin rendering
	Groups  []AdminGroupView
	Error   string
	Success string
	// Notifications available for selection in monitor forms
	Notifications []config.NotificationConfig
}

// StatusMonitorView is a view model of monitor state.
type StatusMonitorView struct {
	ID          string
	Name        string
	Type        monitor.Type
	Target      string
	Enabled     bool
	Status      monitor.Status
	LastChecked time.Time
	LastChange  time.Time
	LastLatency time.Duration
	LastMessage string
	History     []monitor.CheckResult
	SuccessRate float64
	GroupID     int
	Group       string
	Order       int
	MasterID    string
	MasterDown  bool
}

// AdminMonitorView extends StatusMonitorView with configuration options.
type AdminMonitorView struct {
	StatusMonitorView
	IntervalSeconds int
	TimeoutSeconds  int
	NotifyURL       string
	FailThreshold   int
	NotificationID  int
	CertValidation  string
}

const historyPreview = 20

func toStatusMonitorView(snap monitor.Snapshot) StatusMonitorView {
	success := 0
	for _, h := range snap.History {
		if h.Success {
			success++
		}
	}
	rate := 0.0
	if len(snap.History) > 0 {
		rate = (float64(success) / float64(len(snap.History))) * 100
	}
	start := 0
	if len(snap.History) > historyPreview {
		start = len(snap.History) - historyPreview
	}
	history := make([]monitor.CheckResult, len(snap.History)-start)
	copy(history, snap.History[start:])
	return StatusMonitorView{
		ID:          snap.Config.ID,
		Name:        snap.Config.Name,
		Type:        snap.Config.Type,
		Target:      snap.Config.Target,
		Enabled:     snap.Config.Enabled,
		Status:      snap.Status,
		LastChecked: snap.LastChecked,
		LastChange:  snap.LastChange,
		LastLatency: snap.LastLatency,
		LastMessage: snap.LastMessage,
		History:     history,
		SuccessRate: rate,
		GroupID:     snap.Config.GroupID,
		Group:       snap.Config.Group,
		Order:       snap.Config.Order,
		MasterID:    snap.Config.MasterID,
	}
}

func toAdminMonitorView(snap monitor.Snapshot) AdminMonitorView {
	view := toStatusMonitorView(snap)
	return AdminMonitorView{
		StatusMonitorView: view,
		IntervalSeconds:   int(snap.Config.Interval / time.Second),
		TimeoutSeconds:    int(snap.Config.Timeout / time.Second),
		NotifyURL:         snap.Config.NotifyURL,
		FailThreshold:     snap.Config.FailThreshold,
		NotificationID:    snap.Config.NotificationID,
		CertValidation:    string(snap.Config.CertValidation),
	}
}

func (s *Server) handleInstall(w http.ResponseWriter, r *http.Request) {
	// If installation is not required anymore, do not allow accessing /install
	if !s.installRequired {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		data := struct {
			BasePageData
			Error string
		}{
			BasePageData: BasePageData{
				Title:           "Install Upturtle",
				ContentTemplate: "install.content",
				HideHeader:      true,
				CSRFToken:       s.getCSRFToken(r),
			},
			Error: r.URL.Query().Get("error"),
		}
		if err := s.templates.ExecuteTemplate(w, "install.gohtml", data); err != nil {
			s.logger.Printf("install template error: %v", err)
			http.Error(w, "template error", http.StatusInternalServerError)
		}
		return
	}
	if r.Method == http.MethodPost {
		// Validate CSRF token for install form
		if !s.validateCSRFToken(r) {
			http.Error(w, "CSRF token validation failed", http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		user := strings.TrimSpace(r.FormValue("username"))
		pass := r.FormValue("password")
		storageType := r.FormValue("storage_type")
		sqlitePath := strings.TrimSpace(r.FormValue("sqlite_path"))

		if user == "" || pass == "" {
			http.Redirect(w, r, "/install?error=Username+and+password+are+required", http.StatusSeeOther)
			return
		}

		// Validate storage configuration
		var dbConfig *database.Config
		if storageType == "sqlite" {
			if sqlitePath == "" {
				sqlitePath = "/data/upturtle.db" // Default path
			}
			dbConfig = &database.Config{
				Type: database.DatabaseTypeSQLite,
				Path: sqlitePath,
			}

			// Validate the database configuration
			if err := database.ValidateConfig(*dbConfig); err != nil {
				http.Redirect(w, r, "/install?error=Invalid+database+configuration:+"+url.QueryEscape(err.Error()), http.StatusSeeOther)
				return
			}
		}
		// For "memory" storage type, dbConfig remains nil
		hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		if err != nil {
			s.logger.Printf("failed to hash password: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.adminUser = user
		s.adminPassword = string(hash)
		s.databaseConfig = dbConfig
		s.installRequired = false

		// Initialize database if configured
		if dbConfig != nil {
			s.logger.Printf("Initializing database during installation: %s", dbConfig.Type)
			db, err := database.NewDatabase(*dbConfig)
			if err != nil {
				s.logger.Printf("Failed to create database during installation: %v", err)
				http.Redirect(w, r, "/install?error=Failed+to+create+database:+"+url.QueryEscape(err.Error()), http.StatusSeeOther)
				return
			}

			if err := db.Initialize(); err != nil {
				s.logger.Printf("Failed to initialize database during installation: %v", err)
				http.Redirect(w, r, "/install?error=Failed+to+initialize+database:+"+url.QueryEscape(err.Error()), http.StatusSeeOther)
				return
			}

			// Set up database integration for the manager
			dbIntegration := monitor.NewDatabaseIntegration(db)
			s.manager.SetDatabaseIntegration(dbIntegration)
			s.logger.Printf("Database integration enabled during installation")

			// Set the persistent config database connection
			s.configDB = db

			// Store admin credentials in database for future use
			if err := db.SaveSetting("admin_username", user); err != nil {
				s.logger.Printf("Warning: Failed to save admin username to database: %v", err)
			}
			if err := db.SaveSetting("admin_password_hash", string(hash)); err != nil {
				s.logger.Printf("Warning: Failed to save admin password hash to database: %v", err)
			} else {
				s.logger.Printf("Admin credentials saved to database")
			}

			// Store all other configurations in database as well
			if len(s.groups) > 0 {
				for _, group := range s.groups {
					groupData := database.GroupData{
						ID:    group.ID,
						Name:  group.Name,
						Order: group.Order,
					}
					if _, err := db.SaveGroup(groupData); err != nil {
						s.logger.Printf("Warning: Failed to save group %s to database: %v", group.Name, err)
					}
				}
			}
			if len(s.notifications) > 0 {
				for _, notification := range s.notifications {
					notificationData := database.NotificationData{
						ID:   notification.ID,
						Name: notification.Name,
						URL:  notification.URL,
					}
					if _, err := db.SaveNotification(notificationData); err != nil {
						s.logger.Printf("Warning: Failed to save notification %s to database: %v", notification.Name, err)
					}
				}
			}

			// Save UI setting (ShowMemoryDisplay) to database under 'settings'
			if s.showMemoryDisplay {
				if err := db.SaveSetting("show_memory_display", "true"); err != nil {
					s.logger.Printf("Warning: Failed to save UI settings to database during install: %v", err)
				}
			}

			// Store monitors to database as well
			configs := s.manager.GetAllConfigs()
			for _, mc := range configs {
				monitorData := database.MonitorData{
					ID:             mc.ID,
					Name:           mc.Name,
					Type:           string(mc.Type),
					Target:         mc.Target,
					IntervalSec:    int(mc.Interval / time.Second),
					TimeoutSec:     int(mc.Timeout / time.Second),
					NotificationID: mc.NotificationID,
					Enabled:        mc.Enabled,
					GroupID:        mc.GroupID,
					Order:          mc.Order,
					MasterID:       mc.MasterID,
					FailThreshold:  mc.FailThreshold,
					CertValidation: string(mc.CertValidation),
				}
				if err := s.configDB.SaveMonitor(monitorData); err != nil {
					s.logger.Printf("Warning: Failed to save monitor %s to database: %v", mc.Name, err)
				}
			}
		}
		// If no monitors are configured yet, add sensible defaults as requested.
		if len(s.manager.List()) == 0 {
			// Ensure default group exists first with ID=1
			var gid int = 1
			if len(s.groups) == 0 {
				// If database is configured, create group in database first to get proper ID
				if s.databaseConfig != nil && s.configDB != nil {
					groupData := database.GroupData{
						Name:  "Google",
						Order: 1,
					}
					savedGroup, dbErr := s.configDB.SaveGroup(groupData)
					if dbErr != nil {
						s.logger.Printf("Failed to save default group to database: %v", dbErr)
						// Fallback to in-memory only with ID=1
						gid = 1
					} else {
						gid = savedGroup.ID
					}
				}
				s.groups = []config.GroupConfig{{ID: gid, Name: "Google", Order: 1}}
				s.nextGroupID = gid + 1
			} else {
				gid = s.groups[0].ID
			}
			defaultMon1 := monitor.MonitorConfig{
				Name:      "Google DNS 1",
				Type:      monitor.TypeICMP,
				Target:    "8.8.8.8",
				Interval:  20 * time.Second,
				Timeout:   10 * time.Second,
				NotifyURL: "",
				Enabled:   true,
				GroupID:   gid,
				Order:     1,
			}
			if _, err := s.manager.AddMonitor(defaultMon1); err != nil {
				s.logger.Printf("failed to add default monitor 8.8.8.8: %v", err)
			}
			defaultMon2 := monitor.MonitorConfig{
				Name:      "Google DNS 2",
				Type:      monitor.TypeICMP,
				Target:    "8.8.4.4",
				Interval:  20 * time.Second,
				Timeout:   10 * time.Second,
				NotifyURL: "",
				Enabled:   true,
				GroupID:   gid,
				Order:     2,
			}
			if _, err := s.manager.AddMonitor(defaultMon2); err != nil {
				s.logger.Printf("failed to add default monitor 8.8.4.4: %v", err)
			}
		}
		if err := s.saveConfig(); err != nil {
			s.logger.Printf("save config after install: %v", err)
		}
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) persistMonitors() error {
	return s.saveConfig()
}

func (s *Server) saveConfig() error {
	if s.configPath == "" {
		return nil
	}

	// If database is configured, save everything to database and minimal config to file
	if s.databaseConfig != nil && s.configDB != nil {
		// Save admin credentials to database
		s.configDB.SaveSetting("admin_username", s.adminUser)
		s.configDB.SaveSetting("admin_password_hash", s.adminPassword)

		// Save groups to database
		for _, group := range s.groups {
			groupData := database.GroupData{
				ID:    group.ID,
				Name:  group.Name,
				Order: group.Order,
			}
			if _, err := s.configDB.SaveGroup(groupData); err != nil {
				s.logger.Printf("Warning: Failed to save group %s to database: %v", group.Name, err)
			}
		}

		// Save notifications to database
		for _, notification := range s.notifications {
			notificationData := database.NotificationData{
				ID:   notification.ID,
				Name: notification.Name,
				URL:  notification.URL,
			}
			if _, err := s.configDB.SaveNotification(notificationData); err != nil {
				s.logger.Printf("Warning: Failed to save notification %s to database: %v", notification.Name, err)
			}
		}

		// Save UI setting (ShowMemoryDisplay) in the database for DB mode; keep debug flags out of DB
		if s.showMemoryDisplay {
			if err := s.configDB.SaveSetting("show_memory_display", "true"); err != nil {
				s.logger.Printf("Warning: Failed to save UI settings to database: %v", err)
			}
		}

		// Save monitors to database as well
		configs := s.manager.GetAllConfigs()
		for _, mc := range configs {
			monitorData := database.MonitorData{
				ID:             mc.ID,
				Name:           mc.Name,
				Type:           string(mc.Type),
				Target:         mc.Target,
				IntervalSec:    int(mc.Interval / time.Second),
				TimeoutSec:     int(mc.Timeout / time.Second),
				NotificationID: mc.NotificationID,
				Enabled:        mc.Enabled,
				GroupID:        mc.GroupID,
				Order:          mc.Order,
				MasterID:       mc.MasterID,
				FailThreshold:  mc.FailThreshold,
				CertValidation: string(mc.CertValidation),
			}
			if err := s.configDB.SaveMonitor(monitorData); err != nil {
				s.logger.Printf("Warning: Failed to save monitor %s to database: %v", mc.Name, err)
			}
		}

		// Save only database config and debug flags to config file in DB mode
		// Create a minimal config structure to avoid empty fields
		minimalCfg := struct {
			Database          *database.Config `json:"database,omitempty"`
			MonitorDebug      bool             `json:"monitor_debug,omitempty"`
			NotificationDebug bool             `json:"notification_debug,omitempty"`
			ApiDebug          bool             `json:"api_debug,omitempty"`
			AuthDebug         bool             `json:"auth_debug,omitempty"`
		}{
			Database:          s.databaseConfig,
			MonitorDebug:      s.monitorDebug,
			NotificationDebug: s.notificationDebug,
			ApiDebug:          s.apiDebug,
			AuthDebug:         s.authDebug,
		}

		// Manually save the minimal config
		if err := os.MkdirAll(filepath.Dir(s.configPath), 0o755); err != nil {
			return fmt.Errorf("ensure config dir: %w", err)
		}
		b, err := json.MarshalIndent(minimalCfg, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal config: %w", err)
		}
		tmp := s.configPath + ".tmp"
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			return fmt.Errorf("write temp config: %w", err)
		}
		if err := os.Rename(tmp, s.configPath); err != nil {
			return fmt.Errorf("atomic replace config: %w", err)
		}
		return nil
	}

	// In-memory mode: save everything to config file
	cfg := config.AppConfig{
		AdminUser:         s.adminUser,
		AdminPasswordHash: s.adminPassword,
		Database:          s.databaseConfig,
	}
	cfg.Groups = append([]config.GroupConfig(nil), s.groups...)
	cfg.Notifications = append([]config.NotificationConfig(nil), s.notifications...)
	cfg.MonitorDebug = s.monitorDebug
	cfg.NotificationDebug = s.notificationDebug
	cfg.ApiDebug = s.apiDebug
	cfg.AuthDebug = s.authDebug
	cfg.ShowMemoryDisplay = s.showMemoryDisplay
	configs := s.manager.GetAllConfigs()
	cfg.Monitors = make([]config.PersistedMonitorConfig, 0, len(configs))
	for _, mc := range configs {
		cfg.Monitors = append(cfg.Monitors, config.FromMonitorConfig(mc))
	}
	return config.Save(s.configPath, cfg)
}

// getNextOrderForGroup calculates the next available order number for monitors in a specific group
func (s *Server) getNextOrderForGroup(groupID int) int {
	snapshots := s.manager.List()
	maxOrder := 0

	// Find the highest order number in the specified group
	for _, snap := range snapshots {
		if snap.Config.GroupID == groupID && snap.Config.Order > maxOrder {
			maxOrder = snap.Config.Order
		}
	}

	return maxOrder + 1
}
