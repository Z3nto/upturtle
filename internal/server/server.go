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
	// user session store: sessionID -> userID
	userSessions map[string]int
	// ordered list of groups for display in UI
	groups []config.GroupConfig
	// list of predefined notifications for selection
	notifications []config.NotificationConfig
	// list of status pages
	statusPages []config.StatusPageConfig
	// next ID counters
	nextGroupID        int
	nextNotificationID int
	nextStatusPageID   int
	// debug flags (also persisted)
	monitorDebug      bool
	notificationDebug bool
	apiDebug          bool
	authDebug         bool
	// UI settings
	showDatabaseDisplay bool
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
	// StatusPages are public status pages
	StatusPages []config.StatusPageConfig
	// Debug flags (persisted in config file)
	MonitorDebug      bool
	NotificationDebug bool
	ApiDebug          bool
	AuthDebug         bool
	// UI settings
	ShowDatabaseDisplay bool
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
		statusPages:       append([]config.StatusPageConfig(nil), cfg.StatusPages...),
		configPath:        cfg.ConfigPath,
		monitorDebug:      cfg.MonitorDebug,
		notificationDebug: cfg.NotificationDebug,
		apiDebug:          cfg.ApiDebug,
		authDebug:         cfg.AuthDebug,
		showDatabaseDisplay: cfg.ShowDatabaseDisplay,
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
	// initialize user session store
	s.userSessions = make(map[string]int)
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
	for _, sp := range s.statusPages {
		if sp.ID >= s.nextStatusPageID {
			s.nextStatusPageID = sp.ID + 1
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
	// Only include default groups (not statuspage-specific groups)
	orderedIDs := make([]int, 0, len(s.groups))
	seen := map[int]bool{}
	for _, gg := range s.groups {
		// Only include default groups
		if gg.Type == "" || gg.Type == config.GroupTypeDefault {
			orderedIDs = append(orderedIDs, gg.ID)
			seen[gg.ID] = true
		}
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
		BasePageData: s.createBasePageData(r, "Administration", "admin.content"),
		Groups:       groups,
		Error:        failure,
		Success:      success,
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

// ---- User Settings page ----
// handleUserSettings renders the user settings page (GET only).
func (s *Server) handleUserSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	data := s.createBasePageData(r, "User Settings", "user-settings.content")
	if err := s.templates.ExecuteTemplate(w, "user-settings.gohtml", data); err != nil {
		s.logger.Printf("user-settings template error: %v", err)
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
		ShowDatabaseDisplay bool
		Error             string
		Success           string
	}{
		BasePageData:      s.createBasePageData(r, "Settings", "settings.content"),
		MonitorDebug:      s.monitorDebug,
		NotificationDebug: s.notificationDebug,
		ApiDebug:          s.apiDebug,
		AuthDebug:         s.authDebug,
		ShowDatabaseDisplay: s.showDatabaseDisplay,
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
		ShowDatabaseDisplay bool   `json:"show_database_display"`
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
	s.showDatabaseDisplay = body.ShowDatabaseDisplay

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

// handleAPIMonitorChart returns chart data for a specific monitor
func (s *Server) handleAPIMonitorChart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.apiDebug {
		s.logger.Printf("[API DEBUG] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	}

	// Extract monitor ID from URL path: /api/monitors/chart/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/monitors/chart/")
	monitorID := strings.TrimSpace(path)

	if monitorID == "" {
		http.Error(w, "monitor ID is required", http.StatusBadRequest)
		return
	}

	// Get monitor snapshot
	snap, err := s.manager.GetSnapshot(monitorID)
	if err != nil {
		http.Error(w, "monitor not found", http.StatusNotFound)
		return
	}

	// Prepare chart data based on monitor type
	chartData := map[string]any{
		"id":   snap.Config.ID,
		"name": snap.Config.Name,
		"type": snap.Config.Type,
	}

	// Collect time series data from history
	timestamps := make([]string, 0, len(snap.History))
	latencies := make([]float64, 0, len(snap.History))
	statuses := make([]int, 0, len(snap.History))

	for _, h := range snap.History {
		timestamps = append(timestamps, h.Timestamp.Format(time.RFC3339))
		latencies = append(latencies, h.Latency.Seconds()*1000) // Convert to milliseconds
		if h.Success {
			statuses = append(statuses, 1)
		} else {
			statuses = append(statuses, 0)
		}
	}

	chartData["timestamps"] = timestamps
	chartData["latencies"] = latencies
	chartData["statuses"] = statuses

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(chartData); err != nil {
		s.logger.Printf("encode monitor chart json: %v", err)
	}
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
	rest = strings.TrimPrefix(rest, "/api/groups")
	rest = strings.Trim(rest, "/")

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
		// Filter to only return default groups (exclude statuspage groups)
		defaultGroups := make([]config.GroupConfig, 0)
		for _, g := range s.groups {
			if g.Type == "" || g.Type == config.GroupTypeDefault {
				defaultGroups = append(defaultGroups, g)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(defaultGroups)
	case http.MethodPost:
		// Check authentication first
		if !s.ensureAuth(w, r) {
			return
		}

		var body struct {
			Name      string `json:"name"`
			Type      string `json:"type"`
			Order     int    `json:"order"`
			CSRFToken string `json:"csrf_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}

		// Validate CSRF token - either from JSON body or from request (form/header)
		if body.CSRFToken != "" {
			// JSON request with csrf_token in body (from statuspage config)
			if !s.validateCSRFTokenFromJSON(r, body.CSRFToken) {
				http.Error(w, "CSRF token validation failed", http.StatusForbidden)
				return
			}
		} else {
			// Form request with csrf_token in form/header (from admin page)
			if !s.validateCSRFToken(r) {
				http.Error(w, "CSRF token validation failed", http.StatusForbidden)
				return
			}
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

		// Use provided order or compute next order as max(Order)+1
		nextOrder := body.Order
		if nextOrder <= 0 {
			nextOrder = 1
			for _, g := range s.groups {
				if g.Order >= nextOrder {
					nextOrder = g.Order + 1
				}
			}
		}

		// Use provided type or default to "default"
		groupType := config.GroupType(body.Type)
		if groupType == "" {
			groupType = config.GroupTypeDefault
		}

		var gid int

		// If database is configured, create group in database first to get proper ID
		if s.databaseConfig != nil && s.configDB != nil {
			groupData := database.GroupData{
				Name:  name,
				Type:  database.GroupType(groupType),
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

		newGroup := config.GroupConfig{
			ID:    gid,
			Name:  name,
			Type:  groupType,
			Order: nextOrder,
		}
		s.groups = append(s.groups, newGroup)

		// Save config (will update database again in DB mode, but with correct ID)
		if err := s.saveConfig(); err != nil {
			s.logger.Printf("persist api group create: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": gid, "name": name, "type": string(groupType), "order": nextOrder})
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
		// First check authentication only
		if !s.ensureAuth(w, r) {
			return
		}
		// Read and validate CSRF token from JSON body
		var body struct {
			CSRFToken string `json:"csrf_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if !s.validateCSRFTokenFromJSON(r, body.CSRFToken) {
			http.Error(w, "CSRF token validation failed", http.StatusForbidden)
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
	s.mux.HandleFunc("/settings", s.ensureInstalled(s.handleUserSettings))
	// Status pages management
	s.mux.HandleFunc("/admin/statuspages", s.ensureInstalled(s.handleAdminStatusPages))
	s.mux.HandleFunc("/admin/statuspages/", s.ensureInstalled(s.handleAdminStatusPages))
	// User management (only available with database auth)
	s.mux.HandleFunc("/admin/users", s.ensureInstalled(s.handleAdminUsers))
	s.mux.HandleFunc("/admin/users/", s.ensureInstalled(s.handleAdminUsers))
	// Note: More specific routes like /admin/statuspages/{id}/config are handled by handleAdminStatusPagesConfig
	// which checks the URL path pattern
	// Group actions go via REST API now; monitor reorder moved to /api/monitors/reorder

	// API endpoints (one handler per resource), support with and without trailing slash
	s.mux.HandleFunc("/api/monitors", s.ensureInstalled(s.handleAPIMonitorsUnified))
	s.mux.HandleFunc("/api/monitors/", s.ensureInstalled(s.handleAPIMonitorsUnified))
	s.mux.HandleFunc("/api/monitors/reorder", s.ensureInstalled(s.handleAPIMonitorsReorder))
	s.mux.HandleFunc("/api/monitors/chart/", s.ensureInstalled(s.handleAPIMonitorChart))
	s.mux.HandleFunc("/api/notifications", s.ensureInstalled(s.handleAPINotificationsUnified))
	s.mux.HandleFunc("/api/notifications/", s.ensureInstalled(s.handleAPINotificationsUnified))
	s.mux.HandleFunc("/api/groups", s.ensureInstalled(s.handleAPIGroupsUnified))
	s.mux.HandleFunc("/api/groups/", s.ensureInstalled(s.handleAPIGroupsUnified))
	s.mux.HandleFunc("/api/settings", s.ensureInstalled(s.handleAPISettings))
	s.mux.HandleFunc("/api/history/", s.ensureInstalled(s.handleAPIHistory))
	s.mux.HandleFunc("/api/statuspages", s.ensureInstalled(s.handleAPIStatusPagesUnified))
	s.mux.HandleFunc("/api/statuspages/", s.ensureInstalled(s.handleAPIStatusPagesUnified))
	s.mux.HandleFunc("/api/users", s.ensureInstalled(s.handleAPIUsersUnified))
	s.mux.HandleFunc("/api/users/", s.ensureInstalled(s.handleAPIUsersUnified))
	s.mux.HandleFunc("/api/apikeys", s.ensureInstalled(s.handleAPIListAPIKeys))
	s.mux.HandleFunc("/api/apikeys/generate", s.ensureInstalled(s.handleAPIGenerateAPIKey))
	s.mux.HandleFunc("/api/apikeys/revoke", s.ensureInstalled(s.handleAPIRevokeAPIKey))

	// Public status page endpoints
	s.mux.HandleFunc("/status/", s.handlePublicStatusPage)
	s.mux.HandleFunc("/api/public/status/", s.handlePublicStatusPageAPI)
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
			BasePageData:  s.createBasePageData(r, "Notifications", "notifications.content"),
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
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; connect-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

	// If installation is required, redirect all requests to /install
	// until credentials are configured, except when already on /install.
	if s.installRequired && r.URL.Path != "/install" && !strings.HasPrefix(r.URL.Path, "/static/") {
		http.Redirect(w, r, "/install", http.StatusSeeOther)
		return
	}

	// Enforce authentication and authorization
	if (s.adminUser != "" && s.adminPassword != "") || s.isUsingDatabaseAuth() {
		isPublic := s.isPublicPath(r.URL.Path)
		currentUser := s.getCurrentUser(r)
		isAuth := currentUser != nil

		// Check for API key authentication (for API requests only)
		if !isAuth && strings.HasPrefix(r.URL.Path, "/api/") {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				apiKey := strings.TrimPrefix(authHeader, "Bearer ")
				if apiKey != "" && s.configDB != nil {
					user, err := s.validateAPIKey(apiKey)
					if err == nil && user != nil {
						s.authDebugf("API key authentication successful for user %s", user.Username)
						currentUser = user
						isAuth = true
					} else {
						s.authDebugf("API key authentication failed: %v", err)
					}
				}
			}
		}

		// If no session but remember-me cookie exists, try to auto-login
		if !isAuth && !isPublic {
			if rememberCookie, err := r.Cookie("upturtle_remember"); err == nil && rememberCookie.Value != "" {
				user, err := s.validateRememberMeToken(rememberCookie.Value)
				if err == nil && user != nil {
					s.authDebugf("Auto-login via remember-me token for user %s", user.Username)
					// Create a new session with the remember-me flag
					if err := s.createUserSession(w, r, user, true); err != nil {
						s.logger.Printf("[ERROR] Failed to create session from remember-me: %v", err)
					} else {
						currentUser = user
						isAuth = true
					}
				} else if err != nil {
					s.authDebugf("Remember-me token validation failed: %v", err)
				}
			}
		}

		s.authDebugf("Auth middleware: path='%s', isPublic=%t, isAuthenticated=%t", r.URL.Path, isPublic, isAuth)

		if isAuth {
			s.authDebugf("Authenticated user: %s (role: %s)", currentUser.Username, currentUser.Role)
		}

		if !isPublic {
			if !isAuth {
				s.authDebugf("Unauthenticated request to %s", r.URL.Path)
				// For API requests, return JSON error instead of redirecting
				if strings.HasPrefix(r.URL.Path, "/api/") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					json.NewEncoder(w).Encode(map[string]string{
						"error": "unauthorized",
						"message": "Authentication required",
					})
					return
				}
				// For web pages, redirect to login
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			// Check role-based permissions
			if !s.hasPermission(currentUser, r.URL.Path) {
				s.authDebugf("Access denied for user %s (role: %s) to path %s", currentUser.Username, currentUser.Role, r.URL.Path)
				// For API requests, return JSON error
				if strings.HasPrefix(r.URL.Path, "/api/") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(map[string]string{
						"error": "forbidden",
						"message": "Access denied",
					})
					return
				}
				// For web pages, return HTTP error
				http.Error(w, "Access denied", http.StatusForbidden)
				return
			}
		} else {
			// For public paths, we still log if user is authenticated for debugging
			if isAuth {
				s.authDebugf("Public path accessed by authenticated user: %s (role: %s)", currentUser.Username, currentUser.Role)
			}
		}
	}

	s.mux.ServeHTTP(w, r)
}

// isPublicPath returns true for endpoints that do not require login.
func (s *Server) isPublicPath(p string) bool {
	// Allow login, install (only while install is required), and all assets under /static/
	if p == "/login" || (p == "/install" && s.installRequired) || strings.HasPrefix(p, "/static/") || strings.HasPrefix(p, "/status/") || strings.HasPrefix(p, "/api/public/") {
		return true
	}
	return false
}

// ==== User Management & Role-Based Access Control ===========================

// getCurrentUser returns the current user from session, API key, or nil if not authenticated
// Note: Remember-me token validation is handled in the auth middleware
func (s *Server) getCurrentUser(r *http.Request) *database.UserData {
	// First, try API key authentication (for API requests)
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		apiKey := strings.TrimPrefix(authHeader, "Bearer ")
		if apiKey != "" && s.configDB != nil {
			user, err := s.validateAPIKey(apiKey)
			if err == nil && user != nil {
				return user
			}
		}
	}

	// Fall back to session-based authentication
	sessionID := s.getSessionID(r)
	if sessionID == "" {
		return nil
	}

	// Check if session exists and is valid
	if expiry, exists := s.sessions[sessionID]; !exists || time.Now().After(expiry) {
		return nil
	}

	// Get user ID from session
	userID, exists := s.userSessions[sessionID]
	if !exists {
		return nil
	}

	// Find user in cache or database
	if s.configDB != nil {
		// Use database
		user, err := s.configDB.GetUser(userID)
		if err != nil || !user.Enabled {
			return nil
		}
		return user
	}

	// Legacy mode: check if this is the admin user
	if s.adminUser != "" && userID == -1 {
		return &database.UserData{
			ID:       -1,
			Username: s.adminUser,
			Role:     database.UserRoleAdmin,
			Enabled:  true,
		}
	}

	return nil
}

// hasPermission checks if the current user has permission for the given path
func (s *Server) hasPermission(user *database.UserData, path string) bool {
	if user == nil {
		return false
	}

	if !user.Enabled {
		return false
	}

	switch user.Role {
	case database.UserRoleAdmin:
		// Admin can access everything
		return true
	case database.UserRoleWrite:
		// Write users can access admin, notifications, and status pages
		if path == "/" || strings.HasPrefix(path, "/static/") || strings.HasPrefix(path, "/status/") || strings.HasPrefix(path, "/logout") {
			return true
		}
		if path == "/admin" || strings.HasPrefix(path, "/admin/notifications") || strings.HasPrefix(path, "/admin/statuspages") {
			return true
		}
		if strings.HasPrefix(path, "/api/") && !strings.HasPrefix(path, "/api/users") {
			return true
		}
		return false
	case database.UserRoleReadOnly:
		// ReadOnly users can only access main status page and public resources
		if path == "/" || strings.HasPrefix(path, "/static/") || strings.HasPrefix(path, "/status/") || strings.HasPrefix(path, "/logout") {
			return true
		}
		if strings.HasPrefix(path, "/api/public/") || strings.HasPrefix(path, "/api/status") || strings.HasPrefix(path, "/api/memory") {
			return true
		}
		return false
	default:
		return false
	}
}

// isUsingDatabaseAuth returns true if the system is using database-based authentication
func (s *Server) isUsingDatabaseAuth() bool {
	return s.configDB != nil
}

// authenticateUser validates username/password and returns user data
func (s *Server) authenticateUser(username, password string) (*database.UserData, error) {
	if s.configDB != nil {
		// Database mode: authenticate against users table
		user, err := s.configDB.GetUserByUsername(username)
		if err != nil {
			return nil, fmt.Errorf("user not found")
		}

		if !user.Enabled {
			return nil, fmt.Errorf("user disabled")
		}

		// Verify password
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
			return nil, fmt.Errorf("invalid password")
		}

		return user, nil
	} else {
		// Legacy mode: authenticate against admin credentials
		if username == s.adminUser && s.adminPassword != "" {
			if err := bcrypt.CompareHashAndPassword([]byte(s.adminPassword), []byte(password)); err != nil {
				return nil, fmt.Errorf("invalid password")
			}

			return &database.UserData{
				ID:       -1, // Special ID for legacy admin
				Username: s.adminUser,
				Role:     database.UserRoleAdmin,
				Enabled:  true,
			}, nil
		}

		return nil, fmt.Errorf("user not found")
	}
}

// createUserSession creates a session for the authenticated user
// If rememberMe is true, also creates a persistent remember-me token
func (s *Server) createUserSession(w http.ResponseWriter, r *http.Request, user *database.UserData, rememberMe bool) error {
	s.authDebugf("Creating session for user %s with role %s, rememberMe=%v", user.Username, user.Role, rememberMe)

	// Generate session ID
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		s.logger.Printf("[ERROR] Failed to generate session ID: %v", err)
		return err
	}
	sessionID := hex.EncodeToString(b)

	// Clean up any temporary CSRF token for this client
	tempKey := "temp_" + r.RemoteAddr + "_" + r.UserAgent()
	delete(s.csrfTokens, tempKey)

	// Check if request is over HTTPS
	isHTTPS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"

	if rememberMe {
		// Create persistent remember-me token (30 days)
		if err := s.createRememberMeToken(w, r, user, isHTTPS); err != nil {
			s.logger.Printf("[ERROR] Failed to create remember-me token: %v", err)
			// Continue with session creation even if remember-me fails
		}
		
		// For remember-me, create a session without expiry (browser session)
		s.sessions[sessionID] = time.Now().Add(24 * time.Hour) // Still track in memory
		s.userSessions[sessionID] = user.ID
		
		// Set session cookie without Expires (session cookie)
		cookie := &http.Cookie{
			Name:     "upturtle_session",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   isHTTPS,
		}
		http.SetCookie(w, cookie)
	} else {
		// Regular session (24 hours)
		expiry := time.Now().Add(24 * time.Hour)
		s.sessions[sessionID] = expiry
		s.userSessions[sessionID] = user.ID
		
		// Set session cookie with expiry
		cookie := &http.Cookie{
			Name:     "upturtle_session",
			Value:    sessionID,
			Path:     "/",
			Expires:  expiry,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   isHTTPS,
		}
		http.SetCookie(w, cookie)
	}

	s.authDebugf("User session created: user=%s, role=%s, sessionID=%s", user.Username, user.Role, sessionID[:8]+"...")
	return nil
}

// destroyUserSession destroys the current user session and remember-me token
func (s *Server) destroyUserSession(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("upturtle_session")
	if err == nil && c.Value != "" {
		delete(s.sessions, c.Value)
		delete(s.userSessions, c.Value)
		delete(s.csrfTokens, c.Value)
	}

	// Also destroy remember-me token if present
	if rememberCookie, err := r.Cookie("upturtle_remember"); err == nil && rememberCookie.Value != "" {
		s.destroyRememberMeToken(rememberCookie.Value)
	}

	// Clean up any temporary CSRF tokens for this client
	tempKey := "temp_" + r.RemoteAddr + "_" + r.UserAgent()
	delete(s.csrfTokens, tempKey)

	// Check if request is over HTTPS
	isHTTPS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"

	// Clear session cookie
	cookie := &http.Cookie{
		Name:     "upturtle_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPS,
	}
	http.SetCookie(w, cookie)
	
	// Clear remember-me cookie
	rememberCookie := &http.Cookie{
		Name:     "upturtle_remember",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPS,
	}
	http.SetCookie(w, rememberCookie)
}

// createRememberMeToken creates a persistent remember-me token
func (s *Server) createRememberMeToken(w http.ResponseWriter, r *http.Request, user *database.UserData, isHTTPS bool) error {
	if s.configDB == nil {
		return fmt.Errorf("database not available for remember-me tokens")
	}

	// Generate selector (public identifier) and validator (secret)
	selectorBytes := make([]byte, 16)
	validatorBytes := make([]byte, 32)
	
	if _, err := rand.Read(selectorBytes); err != nil {
		return fmt.Errorf("failed to generate selector: %w", err)
	}
	if _, err := rand.Read(validatorBytes); err != nil {
		return fmt.Errorf("failed to generate validator: %w", err)
	}
	
	selector := hex.EncodeToString(selectorBytes)
	validator := hex.EncodeToString(validatorBytes)
	
	// Hash the validator before storing (bcrypt for security)
	validatorHash, err := bcrypt.GenerateFromPassword([]byte(validator), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash validator: %w", err)
	}
	
	// Get client info
	userAgent := r.UserAgent()
	ipAddress := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ipAddress = forwarded
	}
	
	// Create token (30 days expiry)
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	token := database.RememberMeToken{
		UserID:     user.ID,
		Selector:   selector,
		TokenHash:  string(validatorHash),
		ExpiresAt:  expiresAt,
		LastUsedAt: time.Now(),
		UserAgent:  userAgent,
		IPAddress:  ipAddress,
	}
	
	// Save to database
	savedToken, err := s.configDB.SaveRememberMeToken(token)
	if err != nil {
		return fmt.Errorf("failed to save remember-me token: %w", err)
	}
	
	// Set cookie with selector:validator
	cookieValue := selector + ":" + validator
	cookie := &http.Cookie{
		Name:     "upturtle_remember",
		Value:    cookieValue,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPS,
	}
	http.SetCookie(w, cookie)
	
	s.authDebugf("Remember-me token created for user %s, ID=%d, expires=%s", user.Username, savedToken.ID, expiresAt.Format(time.RFC3339))
	return nil
}

// validateAPIKey validates an API key using selector:token format
func (s *Server) validateAPIKey(apiKey string) (*database.UserData, error) {
	if s.configDB == nil {
		return nil, fmt.Errorf("database not available")
	}

	// Parse API key (format: upt_selector:token)
	if !strings.HasPrefix(apiKey, "upt_") {
		return nil, fmt.Errorf("invalid API key format")
	}

	parts := strings.SplitN(strings.TrimPrefix(apiKey, "upt_"), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid API key format")
	}

	selector := parts[0]
	token := parts[1]

	// Get API key from database by selector
	keyData, err := s.configDB.GetAPIKeyBySelector(selector)
	if err != nil {
		return nil, fmt.Errorf("API key not found")
	}

	// Verify token hash
	if err := bcrypt.CompareHashAndPassword([]byte(keyData.TokenHash), []byte(token)); err != nil {
		return nil, fmt.Errorf("invalid API key")
	}

	// Get user
	user, err := s.configDB.GetUser(keyData.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Check if user is enabled
	if !user.Enabled {
		return nil, fmt.Errorf("user disabled")
	}

	// Update last used timestamp
	go s.configDB.UpdateAPIKeyLastUsed(keyData.ID, time.Now())

	return user, nil
}

// validateRememberMeToken validates and uses a remember-me token
func (s *Server) validateRememberMeToken(cookieValue string) (*database.UserData, error) {
	if s.configDB == nil {
		return nil, fmt.Errorf("database not available")
	}
	
	// Parse cookie value (selector:validator)
	parts := strings.Split(cookieValue, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}
	
	selector := parts[0]
	validator := parts[1]
	
	// Get token from database
	token, err := s.configDB.GetRememberMeToken(selector)
	if err != nil {
		return nil, fmt.Errorf("token not found: %w", err)
	}
	
	// Check if expired
	if time.Now().After(token.ExpiresAt) {
		s.configDB.DeleteRememberMeToken(token.ID)
		return nil, fmt.Errorf("token expired")
	}
	
	// Verify validator hash
	if err := bcrypt.CompareHashAndPassword([]byte(token.TokenHash), []byte(validator)); err != nil {
		// Invalid token - possible theft, delete all tokens for this user
		s.logger.Printf("[SECURITY] Invalid remember-me token for user ID %d, deleting all tokens", token.UserID)
		s.configDB.DeleteRememberMeTokensByUser(token.UserID)
		return nil, fmt.Errorf("invalid token")
	}
	
	// Update last used timestamp
	if err := s.configDB.UpdateRememberMeTokenLastUsed(token.ID, time.Now()); err != nil {
		s.logger.Printf("[WARN] Failed to update token last used: %v", err)
	}
	
	// Get user
	user, err := s.configDB.GetUser(token.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	
	// Check if user is still enabled
	if !user.Enabled {
		s.configDB.DeleteRememberMeToken(token.ID)
		return nil, fmt.Errorf("user disabled")
	}
	
	s.authDebugf("Remember-me token validated for user %s", user.Username)
	return user, nil
}

// destroyRememberMeToken destroys a remember-me token by cookie value
func (s *Server) destroyRememberMeToken(cookieValue string) {
	if s.configDB == nil {
		return
	}
	
	parts := strings.Split(cookieValue, ":")
	if len(parts) != 2 {
		return
	}
	
	selector := parts[0]
	token, err := s.configDB.GetRememberMeToken(selector)
	if err != nil {
		return
	}
	
	if err := s.configDB.DeleteRememberMeToken(token.ID); err != nil {
		s.logger.Printf("[WARN] Failed to delete remember-me token: %v", err)
	}
}

// ==== Auth & Sessions =========================================================

// handleLogin renders and processes the login form.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Check if any authentication is configured
	if (s.adminUser == "" || s.adminPassword == "") && !s.isUsingDatabaseAuth() {
		// No credentials configured; nothing to log in to.
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Check if already authenticated
	if s.getCurrentUser(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	switch r.Method {
	case http.MethodGet:
		// Prevent caching of login page to ensure fresh CSRF tokens
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		
		s.authDebugf("Login GET request from %s, User-Agent: %s", r.RemoteAddr, r.UserAgent())
		csrfToken := s.getCSRFToken(r)
		s.authDebugf("Generated CSRF token for login form: %s...", csrfToken[:10])

		data := struct {
			BasePageData
			Error              string
			ShowRememberMe     bool
		}{
			BasePageData: BasePageData{
				Title:           "Login",
				ContentTemplate: "login.content",
				HideHeader:      true,
				CSRFToken:       csrfToken,
			},
			Error:          r.URL.Query().Get("error"),
			ShowRememberMe: s.configDB != nil, // Only show if database is available
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
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		rememberMe := r.FormValue("remember_me") == "1"
		s.authDebugf("Login attempt: username='%s', password_length=%d, remember_me=%v", username, len(password), rememberMe)

		// Authenticate user using new system
		user, err := s.authenticateUser(username, password)
		if err != nil {
			s.authDebugf("Login failed for user '%s': %v", username, err)
			http.Redirect(w, r, "/login?error="+url.QueryEscape("invalid credentials"), http.StatusSeeOther)
			return
		}

		s.authDebugf("Login successful for user '%s' with role '%s', creating session", user.Username, user.Role)
		if err := s.createUserSession(w, r, user, rememberMe); err != nil {
			s.logger.Printf("[ERROR] create session error: %v", err)
			http.Redirect(w, r, "/login?error="+url.QueryEscape("internal error"), http.StatusSeeOther)
			return
		}
		s.authDebugf("Session created successfully, redirecting to /")
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleLogout clears the session and redirects to login.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.destroyUserSession(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
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

	// Skip CSRF check for API key authentication (Bearer token)
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
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
	// Store it with a key based on remote address and user agent
	tempKey := "temp_" + r.RemoteAddr + "_" + r.UserAgent()
	s.authDebugf("Using CSRF key: '%s'", tempKey)

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
	// Skip CSRF check for API key authentication (Bearer token)
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		s.authDebugf("CSRF validation skipped: API key authentication detected")
		return true
	}

	// Skip CSRF check for HTTP Basic Auth (API clients)
	if _, _, ok := r.BasicAuth(); ok {
		s.authDebugf("CSRF validation skipped: HTTP Basic Auth detected")
		return true
	}

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
		// Use RemoteAddr + UserAgent to differentiate between devices
		tokenKey = "temp_" + r.RemoteAddr + "_" + r.UserAgent()
		expectedToken, exists = s.csrfTokens[tokenKey]
		s.authDebugf("CSRF: Using temporary token, key='%s', exists=%t", tokenKey, exists)
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
	// Skip CSRF check for API key authentication (Bearer token)
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return true
	}

	// Skip CSRF check for HTTP Basic Auth (API clients)
	if _, _, ok := r.BasicAuth(); ok {
		return true
	}

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

	// Clean up expired remember-me tokens from database
	tokensRemoved := 0
	if s.configDB != nil {
		if err := s.configDB.CleanupExpiredRememberMeTokens(); err != nil {
			s.logger.Printf("Failed to cleanup expired remember-me tokens: %v", err)
		} else {
			tokensRemoved++
		}
	}

	if len(expiredSessions) > 0 || tempTokensRemoved > 0 || tokensRemoved > 0 {
		s.logger.Printf("Cleaned up %d expired sessions, %d temporary CSRF tokens, and expired remember-me tokens", len(expiredSessions), tempTokensRemoved)
	}
}

// ==== Status Page =============================================================

// handleStatus serves the main status page
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	data := s.buildStatusData(r)
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

func (s *Server) buildStatusData(r *http.Request) StatusPageData {
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
	// Only include default groups (not statuspage-specific groups)
	orderedIDs := make([]int, 0, len(s.groups))
	seen := map[int]bool{}
	for _, gg := range s.groups {
		// Only include default groups
		if gg.Type == "" || gg.Type == config.GroupTypeDefault {
			orderedIDs = append(orderedIDs, gg.ID)
			seen[gg.ID] = true
		}
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
	baseData := s.createBasePageData(r, "Service Status", "status.content")
	baseData.RefreshSeconds = 0
	baseData.DatabaseEnabled = s.manager.HasDatabaseIntegration()
	baseData.DatabaseHealthy = s.manager.IsDatabaseHealthy()
	baseData.DatabaseError = s.manager.GetDatabaseError()
	
	return StatusPageData{
		BasePageData: baseData,
		Groups:       views,
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
	ShowDatabaseDisplay bool
	// Current user information for menu rendering
	CurrentUser *database.UserData
}

// createBasePageData creates BasePageData with current user information
func (s *Server) createBasePageData(r *http.Request, title, contentTemplate string) BasePageData {
	return BasePageData{
		Title:             title,
		ContentTemplate:   contentTemplate,
		CSRFToken:         s.getCSRFToken(r),
		DatabaseEnabled:   s.configDB != nil,
		ShowDatabaseDisplay: s.showDatabaseDisplay,
		CurrentUser:       s.getCurrentUser(r),
	}
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

// PublicMonitorView is used by public status pages
type PublicMonitorView struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Status       string    `json:"status"`
	LastChecked  time.Time `json:"last_checked"`
	LastLatency  int64     `json:"last_latency"`
	LastChange   time.Time `json:"last_change"`
	LastDownTime time.Time `json:"last_down_time"`
}

// PublicGroupView is used by public status pages
type PublicGroupView struct {
	ID       int                 `json:"id"`
	Name     string              `json:"name"`
	Monitors []PublicMonitorView `json:"monitors"`
}

const historyPreview = 20

// getLastDownTime finds the timestamp of the last failed check in the monitor's history
func getLastDownTime(snap monitor.Snapshot) time.Time {
	// If currently down, return the last change time
	if snap.Status == monitor.StatusDown {
		return snap.LastChange
	}

	// Look through history for the most recent failed check
	for i := len(snap.History) - 1; i >= 0; i-- {
		if !snap.History[i].Success {
			return snap.History[i].Timestamp
		}
	}

	// If no failed checks found in history, return last change time as fallback
	return snap.LastChange
}

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

			// Create admin user in database
			adminUser := database.UserData{
				Username:     user,
				PasswordHash: string(hash),
				Role:         database.UserRoleAdmin,
				Enabled:      true,
			}

			if savedUser, err := db.SaveUser(adminUser); err != nil {
				s.logger.Printf("Warning: Failed to save admin user to database: %v", err)
			} else {
				s.logger.Printf("Admin user '%s' created in database with ID %d", savedUser.Username, savedUser.ID)
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

			// Save UI setting (ShowDatabaseDisplay) to database under 'settings'
			if s.showDatabaseDisplay {
				if err := db.SaveSetting("show_database_display", "true"); err != nil {
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
		// Create or update admin user in database
		if s.adminUser != "" && s.adminPassword != "" {
			adminUser := database.UserData{
				Username:     s.adminUser,
				PasswordHash: s.adminPassword,
				Role:         database.UserRoleAdmin,
				Enabled:      true,
			}

			// Check if admin user already exists
			existingUser, err := s.configDB.GetUserByUsername(s.adminUser)
			if err == nil && existingUser != nil {
				// Update existing user
				adminUser.ID = existingUser.ID
				if _, err := s.configDB.SaveUser(adminUser); err != nil {
					s.logger.Printf("Warning: Failed to update admin user in database: %v", err)
				}
			} else {
				// Create new user
				if _, err := s.configDB.SaveUser(adminUser); err != nil {
					s.logger.Printf("Warning: Failed to save admin user to database: %v", err)
				}
			}
		}

		// Save groups to database
		for _, group := range s.groups {
			groupType := database.GroupType(group.Type)
			// Default to "default" type if not specified
			if groupType == "" {
				groupType = database.GroupTypeDefault
			}
			groupData := database.GroupData{
				ID:    group.ID,
				Name:  group.Name,
				Type:  groupType,
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

		// Save UI setting (ShowDatabaseDisplay) in the database for DB mode; keep debug flags out of DB
		if s.showDatabaseDisplay {
			if err := s.configDB.SaveSetting("show_database_display", "true"); err != nil {
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

		// Save status pages to database
		for _, sp := range s.statusPages {
			pageData := database.StatusPageData{
				ID:     sp.ID,
				Name:   sp.Name,
				Slug:   sp.Slug,
				Active: sp.Active,
			}
			if _, err := s.configDB.SaveStatusPage(pageData); err != nil {
				s.logger.Printf("Warning: Failed to save status page %s to database: %v", sp.Name, err)
			} else {
				// Clear and re-add monitors for this status page
				s.configDB.ClearStatusPageMonitors(sp.ID)
				for _, mon := range sp.Monitors {
					monData := database.StatusPageMonitorData{
						StatusPageID: sp.ID,
						MonitorID:    mon.MonitorID,
						GroupID:      mon.GroupID,
						Order:        mon.Order,
					}
					if err := s.configDB.AddMonitorToStatusPage(monData); err != nil {
						s.logger.Printf("Warning: Failed to add monitor to status page in database: %v", err)
					}
				}
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
	cfg.StatusPages = append([]config.StatusPageConfig(nil), s.statusPages...)
	cfg.MonitorDebug = s.monitorDebug
	cfg.NotificationDebug = s.notificationDebug
	cfg.ApiDebug = s.apiDebug
	cfg.AuthDebug = s.authDebug
	cfg.ShowDatabaseDisplay = s.showDatabaseDisplay
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

// ==== Status Pages Management =================================================

// handleAdminStatusPages renders the status pages list page or config page
func (s *Server) handleAdminStatusPages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if this is a config page request (e.g., /admin/statuspages/123)
	path := strings.TrimPrefix(r.URL.Path, "/admin/statuspages/")
	path = strings.TrimPrefix(path, "/admin/statuspages")
	path = strings.Trim(path, "/")

	if path != "" {
		// This is a config page request (has an ID)
		s.handleAdminStatusPagesConfig(w, r)
		return
	}

	// Otherwise, show the list page
	data := struct {
		BasePageData
		StatusPages []config.StatusPageConfig
		Error       string
		Success     string
	}{
		BasePageData: s.createBasePageData(r, "Status Pages", "statuspages.content"),
		StatusPages:  append([]config.StatusPageConfig(nil), s.statusPages...),
		Error:        r.URL.Query().Get("error"),
		Success:      r.URL.Query().Get("success"),
	}

	if err := s.templates.ExecuteTemplate(w, "statuspages.gohtml", data); err != nil {
		s.logger.Printf("statuspages template error: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// handleAdminStatusPagesConfig renders the configuration page for a specific status page
func (s *Server) handleAdminStatusPagesConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract status page ID from URL path
	path := strings.TrimPrefix(r.URL.Path, "/admin/statuspages/")
	path = strings.Trim(path, "/")
	id, err := strconv.Atoi(path)
	if err != nil {
		http.Error(w, "invalid status page ID", http.StatusBadRequest)
		return
	}

	// Find the status page
	var statusPage *config.StatusPageConfig
	for i := range s.statusPages {
		if s.statusPages[i].ID == id {
			statusPage = &s.statusPages[i]
			break
		}
	}

	if statusPage == nil {
		http.Error(w, "status page not found", http.StatusNotFound)
		return
	}

	// Get all monitors for selection
	snapshots := s.manager.List()

	// Filter groups by type
	defaultGroups := make([]config.GroupConfig, 0)
	statuspageGroups := make([]config.GroupConfig, 0)
	for _, g := range s.groups {
		switch g.Type {
		case "", config.GroupTypeDefault:
			defaultGroups = append(defaultGroups, g)
		case config.GroupTypeStatusPage:
			statuspageGroups = append(statuspageGroups, g)
		}
	}

	data := struct {
		BasePageData
		StatusPage       config.StatusPageConfig
		AllMonitors      []APISnapshot
		Groups           []config.GroupConfig
		StatusPageGroups []config.GroupConfig
		Error            string
		Success          string
	}{
		BasePageData: BasePageData{
			Title:             "Configure Status Page: " + statusPage.Name,
			ContentTemplate:   "statuspage_config.content",
			CSRFToken:         s.getCSRFToken(r),
			ShowDatabaseDisplay: s.showDatabaseDisplay,
		},
		StatusPage:       *statusPage,
		AllMonitors:      make([]APISnapshot, 0, len(snapshots)),
		Groups:           defaultGroups,
		StatusPageGroups: statuspageGroups,
		Error:            r.URL.Query().Get("error"),
		Success:          r.URL.Query().Get("success"),
	}

	// Convert snapshots and ensure Group name is set
	for _, snap := range snapshots {
		apiSnap := convertSnapshotToAPI(snap)
		// If Group name is empty, populate it from GroupID
		if apiSnap.Config.Group == "" && apiSnap.Config.GroupID > 0 {
			apiSnap.Config.Group = s.getGroupName(apiSnap.Config.GroupID)
		}
		data.AllMonitors = append(data.AllMonitors, apiSnap)
	}

	// Sort monitors by GroupID, then Order, then Name for consistent display
	sort.Slice(data.AllMonitors, func(i, j int) bool {
		if data.AllMonitors[i].Config.GroupID != data.AllMonitors[j].Config.GroupID {
			return data.AllMonitors[i].Config.GroupID < data.AllMonitors[j].Config.GroupID
		}
		if data.AllMonitors[i].Config.Order != data.AllMonitors[j].Config.Order {
			return data.AllMonitors[i].Config.Order < data.AllMonitors[j].Config.Order
		}
		return data.AllMonitors[i].Config.Name < data.AllMonitors[j].Config.Name
	})

	if err := s.templates.ExecuteTemplate(w, "statuspage_config.gohtml", data); err != nil {
		s.logger.Printf("statuspage_config template error: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// handlePublicStatusPage renders a public status page
func (s *Server) handlePublicStatusPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract slug from URL
	slug := strings.TrimPrefix(r.URL.Path, "/status/")
	slug = strings.TrimSuffix(slug, "/")

	if slug == "" {
		http.Error(w, "status page not found", http.StatusNotFound)
		return
	}

	// Find the status page by slug
	var statusPage *config.StatusPageConfig
	for i := range s.statusPages {
		if s.statusPages[i].Slug == slug {
			statusPage = &s.statusPages[i]
			break
		}
	}

	if statusPage == nil {
		http.Error(w, "status page not found", http.StatusNotFound)
		return
	}

	// Check if status page is active
	if !statusPage.Active {
		http.Error(w, "status page is not active", http.StatusForbidden)
		return
	}

	// Get all monitor snapshots
	allSnapshots := s.manager.List()
	snapshotMap := make(map[string]monitor.Snapshot)
	for _, snap := range allSnapshots {
		snapshotMap[snap.Config.ID] = snap
	}

	// Build grouped monitors for this status page
	groupMap := make(map[int]*PublicGroupView)

	for _, spMon := range statusPage.Monitors {
		snap, exists := snapshotMap[spMon.MonitorID]
		if !exists {
			continue
		}

		group, exists := groupMap[spMon.GroupID]
		if !exists {
			group = &PublicGroupView{
				ID:       spMon.GroupID,
				Name:     s.getGroupName(spMon.GroupID),
				Monitors: []PublicMonitorView{},
			}
			groupMap[spMon.GroupID] = group
		}

		group.Monitors = append(group.Monitors, PublicMonitorView{
			ID:           snap.Config.ID,
			Name:         snap.Config.Name,
			Status:       string(snap.Status),
			LastChecked:  snap.LastChecked,
			LastLatency:  snap.LastLatency.Nanoseconds() / 1000000,
			LastChange:   snap.LastChange,
			LastDownTime: getLastDownTime(snap),
		})
	}

	// Sort groups by their order in the groups list, then by name
	groups := make([]PublicGroupView, 0, len(groupMap))
	for _, group := range groupMap {
		groups = append(groups, *group)
	}
	sort.Slice(groups, func(i, j int) bool {
		// Find group order
		var orderI, orderJ int
		for _, g := range s.groups {
			if g.ID == groups[i].ID {
				orderI = g.Order
			}
			if g.ID == groups[j].ID {
				orderJ = g.Order
			}
		}
		if orderI != orderJ {
			return orderI < orderJ
		}
		return groups[i].Name < groups[j].Name
	})

	data := struct {
		BasePageData
		StatusPageName string
		Groups         []PublicGroupView
	}{
		BasePageData: BasePageData{
			Title:           statusPage.Name,
			ContentTemplate: "public_status.content",
		},
		StatusPageName: statusPage.Name,
		Groups:         groups,
	}

	if err := s.templates.ExecuteTemplate(w, "public_status.gohtml", data); err != nil {
		s.logger.Printf("public_status template error: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// handlePublicStatusPageAPI returns JSON data for a public status page
func (s *Server) handlePublicStatusPageAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract slug from URL
	slug := strings.TrimPrefix(r.URL.Path, "/api/public/status/")
	slug = strings.TrimSuffix(slug, "/")

	if slug == "" {
		http.Error(w, "status page not found", http.StatusNotFound)
		return
	}

	// Find the status page by slug
	var statusPage *config.StatusPageConfig
	for i := range s.statusPages {
		if s.statusPages[i].Slug == slug {
			statusPage = &s.statusPages[i]
			break
		}
	}

	if statusPage == nil {
		http.Error(w, "status page not found", http.StatusNotFound)
		return
	}

	if !statusPage.Active {
		http.Error(w, "status page not active", http.StatusNotFound)
		return
	}

	// Get all monitor snapshots
	allSnapshots := s.manager.List()
	snapshotMap := make(map[string]monitor.Snapshot)
	for _, snap := range allSnapshots {
		snapshotMap[snap.Config.ID] = snap
	}

	// Build grouped monitors for this status page using the same logic as the template
	groupMap := make(map[int]*PublicGroupView)

	for _, spMon := range statusPage.Monitors {
		snap, exists := snapshotMap[spMon.MonitorID]
		if !exists {
			continue
		}

		group, exists := groupMap[spMon.GroupID]
		if !exists {
			group = &PublicGroupView{
				ID:       spMon.GroupID,
				Name:     s.getGroupName(spMon.GroupID),
				Monitors: []PublicMonitorView{},
			}
			groupMap[spMon.GroupID] = group
		}

		group.Monitors = append(group.Monitors, PublicMonitorView{
			ID:           snap.Config.ID,
			Name:         snap.Config.Name,
			Status:       string(snap.Status),
			LastChecked:  snap.LastChecked,
			LastLatency:  snap.LastLatency.Nanoseconds() / 1000000,
			LastChange:   snap.LastChange,
			LastDownTime: getLastDownTime(snap),
		})
	}

	// Sort groups by their order in the groups list, then by name
	groups := make([]PublicGroupView, 0, len(groupMap))
	for _, group := range groupMap {
		groups = append(groups, *group)
	}
	sort.Slice(groups, func(i, j int) bool {
		// Find group order
		var orderI, orderJ int
		for _, g := range s.groups {
			if g.ID == groups[i].ID {
				orderI = g.Order
			}
			if g.ID == groups[j].ID {
				orderJ = g.Order
			}
		}
		if orderI != orderJ {
			return orderI < orderJ
		}
		return groups[i].Name < groups[j].Name
	})

	// Calculate overall status
	overallStatus := "operational"
	hasDown := false
	hasUnknown := false

	for _, group := range groups {
		for _, monitor := range group.Monitors {
			switch monitor.Status {
			case "down":
				hasDown = true
			case "unknown":
				hasUnknown = true
			}
		}
	}

	if hasDown {
		overallStatus = "down"
	} else if hasUnknown {
		overallStatus = "degraded"
	}

	response := struct {
		StatusPageName string            `json:"status_page_name"`
		OverallStatus  string            `json:"overall_status"`
		Groups         []PublicGroupView `json:"groups"`
		LastUpdated    time.Time         `json:"last_updated"`
	}{
		StatusPageName: statusPage.Name,
		OverallStatus:  overallStatus,
		Groups:         groups,
		LastUpdated:    time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Printf("public_status API error: %v", err)
		http.Error(w, "JSON encoding error", http.StatusInternalServerError)
	}
}

// ==== API: Status Pages =======================================================

// handleAPIStatusPagesUnified handles all status page API operations
func (s *Server) handleAPIStatusPagesUnified(w http.ResponseWriter, r *http.Request) {
	if s.apiDebug {
		s.logger.Printf("[API DEBUG] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	}

	// Authentication required for all status page operations
	if !s.ensureAuth(w, r) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleAPIStatusPagesGet(w, r)
	case http.MethodPost:
		s.handleAPIStatusPagesCreate(w, r)
	case http.MethodPut:
		s.handleAPIStatusPagesUpdate(w, r)
	case http.MethodDelete:
		s.handleAPIStatusPagesDelete(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAPIStatusPagesGet retrieves status page(s)
func (s *Server) handleAPIStatusPagesGet(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/statuspages/")
	path = strings.TrimPrefix(path, "/api/statuspages")
	path = strings.Trim(path, "/")

	if path == "" {
		// Return all status pages
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.statusPages)
		return
	}

	// Return specific status page
	id, err := strconv.Atoi(path)
	if err != nil {
		http.Error(w, "invalid status page ID", http.StatusBadRequest)
		return
	}

	for _, sp := range s.statusPages {
		if sp.ID == id {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(sp)
			return
		}
	}

	http.Error(w, "status page not found", http.StatusNotFound)
}

// handleAPIStatusPagesCreate creates a new status page
func (s *Server) handleAPIStatusPagesCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name      string `json:"name"`
		Slug      string `json:"slug"`
		Active    bool   `json:"active"`
		CSRFToken string `json:"csrf_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if !s.validateCSRFTokenFromJSON(r, body.CSRFToken) {
		http.Error(w, "CSRF token validation failed", http.StatusForbidden)
		return
	}

	if body.Name == "" || body.Slug == "" {
		http.Error(w, "name and slug are required", http.StatusBadRequest)
		return
	}

	// Check for duplicate slug
	for _, sp := range s.statusPages {
		if sp.Slug == body.Slug {
			http.Error(w, "slug already exists", http.StatusConflict)
			return
		}
	}

	// Create status page in database if configured
	var newID int
	if s.databaseConfig != nil && s.configDB != nil {
		pageData := database.StatusPageData{
			Name:   body.Name,
			Slug:   body.Slug,
			Active: body.Active,
		}
		savedPage, err := s.configDB.SaveStatusPage(pageData)
		if err != nil {
			s.logger.Printf("Failed to save status page to database: %v", err)
			http.Error(w, "failed to create status page", http.StatusInternalServerError)
			return
		}
		newID = savedPage.ID
	} else {
		// Generate ID for file-based config
		newID = s.nextStatusPageID
		s.nextStatusPageID++
	}

	newPage := config.StatusPageConfig{
		ID:       newID,
		Name:     body.Name,
		Slug:     body.Slug,
		Active:   body.Active,
		Monitors: []config.StatusPageMonitorConfig{},
	}

	s.statusPages = append(s.statusPages, newPage)

	if err := s.saveConfig(); err != nil {
		s.logger.Printf("Failed to save config after creating status page: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newPage)
}

// handleAPIStatusPagesUpdate updates an existing status page
func (s *Server) handleAPIStatusPagesUpdate(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/statuspages/")
	path = strings.TrimSuffix(path, "/")
	id, err := strconv.Atoi(path)
	if err != nil {
		http.Error(w, "invalid status page ID", http.StatusBadRequest)
		return
	}

	var body struct {
		Name      string                           `json:"name"`
		Slug      string                           `json:"slug"`
		Active    bool                             `json:"active"`
		Monitors  []config.StatusPageMonitorConfig `json:"monitors"`
		CSRFToken string                           `json:"csrf_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if !s.validateCSRFTokenFromJSON(r, body.CSRFToken) {
		http.Error(w, "CSRF token validation failed", http.StatusForbidden)
		return
	}

	// Find and update status page
	found := false
	for i := range s.statusPages {
		if s.statusPages[i].ID == id {
			// Check for slug conflict with other pages
			if body.Slug != s.statusPages[i].Slug {
				for j := range s.statusPages {
					if i != j && s.statusPages[j].Slug == body.Slug {
						http.Error(w, "slug already exists", http.StatusConflict)
						return
					}
				}
			}

			s.statusPages[i].Name = body.Name
			s.statusPages[i].Slug = body.Slug
			s.statusPages[i].Active = body.Active
			s.statusPages[i].Monitors = body.Monitors
			found = true

			// Update in database if configured
			if s.databaseConfig != nil && s.configDB != nil {
				pageData := database.StatusPageData{
					ID:     id,
					Name:   body.Name,
					Slug:   body.Slug,
					Active: body.Active,
				}
				if _, err := s.configDB.SaveStatusPage(pageData); err != nil {
					s.logger.Printf("Failed to update status page in database: %v", err)
				}

				// Update monitors association
				s.configDB.ClearStatusPageMonitors(id)
				for _, mon := range body.Monitors {
					monData := database.StatusPageMonitorData{
						StatusPageID: id,
						MonitorID:    mon.MonitorID,
						GroupID:      mon.GroupID,
						Order:        mon.Order,
					}
					if err := s.configDB.AddMonitorToStatusPage(monData); err != nil {
						s.logger.Printf("Failed to add monitor to status page in database: %v", err)
					}
				}
			}

			break
		}
	}

	if !found {
		http.Error(w, "status page not found", http.StatusNotFound)
		return
	}

	if err := s.saveConfig(); err != nil {
		s.logger.Printf("Failed to save config after updating status page: %v", err)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"success":true}`))
}

// handleAPIStatusPagesDelete deletes a status page
func (s *Server) handleAPIStatusPagesDelete(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/statuspages/")
	path = strings.TrimSuffix(path, "/")
	id, err := strconv.Atoi(path)
	if err != nil {
		http.Error(w, "invalid status page ID", http.StatusBadRequest)
		return
	}

	// Find and remove status page
	found := false
	for i := range s.statusPages {
		if s.statusPages[i].ID == id {
			s.statusPages = append(s.statusPages[:i], s.statusPages[i+1:]...)
			found = true

			// Delete from database if configured
			if s.databaseConfig != nil && s.configDB != nil {
				if err := s.configDB.DeleteStatusPage(id); err != nil {
					s.logger.Printf("Failed to delete status page from database: %v", err)
				}
			}

			break
		}
	}

	if !found {
		http.Error(w, "status page not found", http.StatusNotFound)
		return
	}

	if err := s.saveConfig(); err != nil {
		s.logger.Printf("Failed to save config after deleting status page: %v", err)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"success":true}`))
}

// ==== User Management =========================================================

// handleAdminUsers renders the user management page
func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	// Only allow access if using database authentication
	if !s.isUsingDatabaseAuth() {
		// Render page with disabled state for memory mode
		data := struct {
			BasePageData
			UsingDatabaseAuth bool
			Users             []database.UserData
		}{
			BasePageData:      s.createBasePageData(r, "User Management", "users.content"),
			UsingDatabaseAuth: false,
			Users:             []database.UserData{},
		}

		if err := s.templates.ExecuteTemplate(w, "users.gohtml", data); err != nil {
			s.logger.Printf("users template error: %v", err)
			http.Error(w, "template error", http.StatusInternalServerError)
		}
		return
	}

	// Check if current user has admin permissions
	currentUser := s.getCurrentUser(r)
	if currentUser == nil || currentUser.Role != database.UserRoleAdmin {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// Load users from database
	users, err := s.configDB.GetAllUsers()
	if err != nil {
		s.logger.Printf("Failed to load users: %v", err)
		http.Error(w, "Failed to load users", http.StatusInternalServerError)
		return
	}

	data := struct {
		BasePageData
		UsingDatabaseAuth bool
		Users             []database.UserData
	}{
		BasePageData:      s.createBasePageData(r, "User Management", "users.content"),
		UsingDatabaseAuth: true,
		Users:             users,
	}

	if err := s.templates.ExecuteTemplate(w, "users.gohtml", data); err != nil {
		s.logger.Printf("users template error: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// ==== API: Users ==============================================================

// handleAPIUsersUnified handles all user API operations
func (s *Server) handleAPIUsersUnified(w http.ResponseWriter, r *http.Request) {
	if s.apiDebug {
		s.logger.Printf("[API DEBUG] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	}

	// Only allow access if using database authentication
	if !s.isUsingDatabaseAuth() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "bad_request",
			"message": "User management only available with database authentication",
		})
		return
	}

	// Check if current user has admin permissions
	currentUser := s.getCurrentUser(r)
	if currentUser == nil || currentUser.Role != database.UserRoleAdmin {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "forbidden",
			"message": "Access denied - admin role required",
		})
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/api/users/")
	rest = strings.TrimPrefix(rest, "/api/users")
	rest = strings.Trim(rest, "/")

	if rest == "" {
		// Collection operations
		s.handleAPIUsersCollection(w, r)
	} else {
		// Item operations
		s.handleAPIUsersItem(w, r, rest)
	}
}

// handleAPIUsersCollection handles operations on the users collection
func (s *Server) handleAPIUsersCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleAPIUsersGet(w, r)
	case http.MethodPost:
		s.handleAPIUsersCreate(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAPIUsersItem handles operations on individual users
func (s *Server) handleAPIUsersItem(w http.ResponseWriter, r *http.Request, userID string) {
	switch r.Method {
	case http.MethodGet:
		s.handleAPIUsersGetOne(w, r, userID)
	case http.MethodPut:
		s.handleAPIUsersUpdate(w, r, userID)
	case http.MethodDelete:
		s.handleAPIUsersDelete(w, r, userID)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAPIUsersGet returns all users
func (s *Server) handleAPIUsersGet(w http.ResponseWriter, r *http.Request) {
	users, err := s.configDB.GetAllUsers()
	if err != nil {
		s.logger.Printf("Failed to get users: %v", err)
		http.Error(w, "Failed to get users", http.StatusInternalServerError)
		return
	}

	// Remove password hashes from response for security
	type UserResponse struct {
		ID        int               `json:"id"`
		Username  string            `json:"username"`
		Role      database.UserRole `json:"role"`
		Enabled   bool              `json:"enabled"`
		CreatedAt time.Time         `json:"created_at"`
		UpdatedAt time.Time         `json:"updated_at"`
	}

	var response []UserResponse
	for _, user := range users {
		response = append(response, UserResponse{
			ID:        user.ID,
			Username:  user.Username,
			Role:      user.Role,
			Enabled:   user.Enabled,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleAPIUsersGetOne returns a single user
func (s *Server) handleAPIUsersGetOne(w http.ResponseWriter, r *http.Request, userIDStr string) {
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	user, err := s.configDB.GetUser(userID)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	// Remove password hash from response for security
	type UserResponse struct {
		ID        int               `json:"id"`
		Username  string            `json:"username"`
		Role      database.UserRole `json:"role"`
		Enabled   bool              `json:"enabled"`
		CreatedAt time.Time         `json:"created_at"`
		UpdatedAt time.Time         `json:"updated_at"`
	}

	response := UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Role:      user.Role,
		Enabled:   user.Enabled,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleAPIUsersCreate creates a new user
func (s *Server) handleAPIUsersCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string            `json:"username"`
		Password string            `json:"password"`
		Role     database.UserRole `json:"role"`
		Enabled  bool              `json:"enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.Username == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}
	if req.Password == "" {
		http.Error(w, "password is required", http.StatusBadRequest)
		return
	}
	if req.Role == "" {
		req.Role = database.UserRoleReadOnly // Default role
	}

	// Validate role
	if req.Role != database.UserRoleReadOnly && req.Role != database.UserRoleWrite && req.Role != database.UserRoleAdmin {
		http.Error(w, "invalid role", http.StatusBadRequest)
		return
	}

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Printf("Failed to hash password: %v", err)
		http.Error(w, "Failed to process password", http.StatusInternalServerError)
		return
	}

	// Create user
	user := database.UserData{
		Username:     req.Username,
		PasswordHash: string(passwordHash),
		Role:         req.Role,
		Enabled:      req.Enabled,
	}

	savedUser, err := s.configDB.SaveUser(user)
	if err != nil {
		s.logger.Printf("Failed to create user: %v", err)
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Return created user (without password hash)
	type UserResponse struct {
		ID        int               `json:"id"`
		Username  string            `json:"username"`
		Role      database.UserRole `json:"role"`
		Enabled   bool              `json:"enabled"`
		CreatedAt time.Time         `json:"created_at"`
		UpdatedAt time.Time         `json:"updated_at"`
	}

	response := UserResponse{
		ID:        savedUser.ID,
		Username:  savedUser.Username,
		Role:      savedUser.Role,
		Enabled:   savedUser.Enabled,
		CreatedAt: savedUser.CreatedAt,
		UpdatedAt: savedUser.UpdatedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// handleAPIUsersUpdate updates an existing user
func (s *Server) handleAPIUsersUpdate(w http.ResponseWriter, r *http.Request, userIDStr string) {
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	// Get existing user
	existingUser, err := s.configDB.GetUser(userID)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	var req struct {
		Username string            `json:"username"`
		Password string            `json:"password,omitempty"` // Optional for updates
		Role     database.UserRole `json:"role"`
		Enabled  bool              `json:"enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.Username == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}

	// Validate role
	if req.Role != database.UserRoleReadOnly && req.Role != database.UserRoleWrite && req.Role != database.UserRoleAdmin {
		http.Error(w, "invalid role", http.StatusBadRequest)
		return
	}

	// Update user data
	existingUser.Username = req.Username
	existingUser.Role = req.Role
	existingUser.Enabled = req.Enabled

	// Update password if provided
	if req.Password != "" {
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			s.logger.Printf("Failed to hash password: %v", err)
			http.Error(w, "Failed to process password", http.StatusInternalServerError)
			return
		}
		existingUser.PasswordHash = string(passwordHash)
	}

	// Save updated user
	savedUser, err := s.configDB.SaveUser(*existingUser)
	if err != nil {
		s.logger.Printf("Failed to update user: %v", err)
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	// Return updated user (without password hash)
	type UserResponse struct {
		ID        int               `json:"id"`
		Username  string            `json:"username"`
		Role      database.UserRole `json:"role"`
		Enabled   bool              `json:"enabled"`
		CreatedAt time.Time         `json:"created_at"`
		UpdatedAt time.Time         `json:"updated_at"`
	}

	response := UserResponse{
		ID:        savedUser.ID,
		Username:  savedUser.Username,
		Role:      savedUser.Role,
		Enabled:   savedUser.Enabled,
		CreatedAt: savedUser.CreatedAt,
		UpdatedAt: savedUser.UpdatedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleAPIUsersDelete deletes a user
func (s *Server) handleAPIUsersDelete(w http.ResponseWriter, r *http.Request, userIDStr string) {
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	// Prevent deleting the current user
	currentUser := s.getCurrentUser(r)
	if currentUser != nil && currentUser.ID == userID {
		http.Error(w, "cannot delete current user", http.StatusBadRequest)
		return
	}

	// Check if user exists
	_, err = s.configDB.GetUser(userID)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	// Delete user
	if err := s.configDB.DeleteUser(userID); err != nil {
		s.logger.Printf("Failed to delete user: %v", err)
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"success":true}`))
}

// handleAPIGenerateAPIKey generates a new API key for the current user
func (s *Server) handleAPIGenerateAPIKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	// Get current user
	currentUser := s.getCurrentUser(r)
	if currentUser == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "unauthorized",
			"message": "Authentication required",
		})
		return
	}

	// Generate selector (16 bytes = 32 hex chars)
	selectorBytes := make([]byte, 16)
	if _, err := rand.Read(selectorBytes); err != nil {
		s.logger.Printf("Failed to generate selector: %v", err)
		http.Error(w, "Failed to generate API key", http.StatusInternalServerError)
		return
	}
	selector := hex.EncodeToString(selectorBytes)

	// Generate token (32 bytes = 64 hex chars)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		s.logger.Printf("Failed to generate token: %v", err)
		http.Error(w, "Failed to generate API key", http.StatusInternalServerError)
		return
	}
	token := hex.EncodeToString(tokenBytes)

	// Hash the token
	tokenHash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Printf("Failed to hash token: %v", err)
		http.Error(w, "Failed to hash API key", http.StatusInternalServerError)
		return
	}

	// Save API key to database
	keyData := database.APIKeyData{
		UserID:    currentUser.ID,
		Name:      req.Name,
		Selector:  selector,
		TokenHash: string(tokenHash),
	}

	savedKey, err := s.configDB.SaveAPIKey(keyData)
	if err != nil {
		s.logger.Printf("Failed to save API key: %v", err)
		http.Error(w, "Failed to save API key", http.StatusInternalServerError)
		return
	}

	// Construct full API key (format: upt_selector:token)
	fullAPIKey := fmt.Sprintf("upt_%s:%s", selector, token)

	s.logger.Printf("Generated API key '%s' for user %s (ID: %d)", req.Name, currentUser.Username, currentUser.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"id":      savedKey.ID,
		"api_key": fullAPIKey,
		"message": "API key generated successfully. Please save it securely as it won't be shown again.",
	})
}

// handleAPIRevokeAPIKey revokes an API key by ID
func (s *Server) handleAPIRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID int `json:"id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Get current user
	currentUser := s.getCurrentUser(r)
	if currentUser == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "unauthorized",
			"message": "Authentication required",
		})
		return
	}

	// Verify ownership by getting all keys for user and finding by ID
	keys, err := s.configDB.GetAPIKeysByUser(currentUser.ID)
	if err != nil {
		http.Error(w, "failed to get API keys", http.StatusInternalServerError)
		return
	}

	found := false
	for _, key := range keys {
		if key.ID == req.ID {
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "API key not found or access denied", http.StatusNotFound)
		return
	}

	// Delete API key
	if err := s.configDB.DeleteAPIKey(req.ID); err != nil {
		s.logger.Printf("Failed to revoke API key: %v", err)
		http.Error(w, "Failed to revoke API key", http.StatusInternalServerError)
		return
	}

	s.logger.Printf("Revoked API key ID %d for user %s", req.ID, currentUser.Username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "API key revoked successfully",
	})
}

// handleAPIListAPIKeys lists all API keys for the current user
func (s *Server) handleAPIListAPIKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get current user
	currentUser := s.getCurrentUser(r)
	if currentUser == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "unauthorized",
			"message": "Authentication required",
		})
		return
	}

	// Get all API keys for user
	keys, err := s.configDB.GetAPIKeysByUser(currentUser.ID)
	if err != nil {
		s.logger.Printf("Failed to get API keys: %v", err)
		http.Error(w, "Failed to get API keys", http.StatusInternalServerError)
		return
	}

	// Don't send token hashes to client
	type APIKeyResponse struct {
		ID         int       `json:"id"`
		Name       string    `json:"name"`
		Selector   string    `json:"selector"`
		LastUsedAt time.Time `json:"last_used_at,omitempty"`
		CreatedAt  time.Time `json:"created_at"`
	}

	response := make([]APIKeyResponse, len(keys))
	for i, key := range keys {
		response[i] = APIKeyResponse{
			ID:         key.ID,
			Name:       key.Name,
			Selector:   key.Selector,
			LastUsedAt: key.LastUsedAt,
			CreatedAt:  key.CreatedAt,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"keys":    response,
	})
}
