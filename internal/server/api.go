package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

// ==== API Response Types ======================================================

// APIResponse represents a standardized JSON response
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// APIHandlerFunc is a function that handles API requests and returns data or an error
type APIHandlerFunc func(r *http.Request) (interface{}, int, error)

// ==== Central API Handler =====================================================

// handleAPI is the central handler for all /api/* endpoints
// It routes requests, checks authentication, and sends JSON responses
func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	if s.apiDebug {
		s.logger.Printf("[API DEBUG] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	}

	// Parse the path to determine which endpoint was called
	path := strings.TrimPrefix(r.URL.Path, "/api/")
	
	var handler APIHandlerFunc
	var requireAuth = true // Default: require authentication for security
	var endpointExists bool
	
	// Route to specific handlers based on path and method
	endpointExists, handler, requireAuth = s.routeAPIEndpoint(path, r.Method)
	
	// Check if endpoint exists
	if !endpointExists {
		s.sendJSONError(w, "endpoint not found", http.StatusNotFound)
		return
	}
	
	// Check authentication if required (CSRF is validated in handler from JSON body)
	if requireAuth {
		if !s.ensureAuth(w, r) {
			// ensureAuth already sent response
			return
		}
	}
	
	// Execute the handler
	data, statusCode, err := handler(r)
	
	// Send response
	if err != nil {
		s.sendJSONError(w, err.Error(), statusCode)
		return
	}
	
	s.sendJSONResponse(w, data, statusCode)
}

// routeAPIEndpoint routes all /api/* endpoints to their respective handlers
func (s *Server) routeAPIEndpoint(path, method string) (exists bool, handler APIHandlerFunc, requireAuth bool) {
	requireAuth = true // Default: require auth for security
	
	// Determine the main resource (first path segment)
	parts := strings.SplitN(path, "/", 2)
	resource := parts[0]
	subPath := ""
	if len(parts) > 1 {
		subPath = parts[1]
	}
	
	// Route based on resource type
	switch resource {
	case "monitors":
		return s.routeMonitorsEndpoint(subPath, method)
	case "notifications":
		return s.routeNotificationsEndpoint(subPath, method)
	case "groups":
		return s.routeGroupsEndpoint(subPath, method)
	case "settings":
		return s.routeSettingsEndpoint(subPath, method)
	case "history":
		return s.routeHistoryEndpoint(subPath, method)
	case "statuspages":
		return s.routeStatusPagesEndpoint(subPath, method)
	case "users":
		return s.routeUsersEndpoint(subPath, method)
	case "public":
		return s.routePublicEndpoint(subPath, method)
	case "status":
		return s.routeStatusEndpoint(subPath, method)
	case "memory":
		return s.routeMemoryEndpoint(subPath, method)
	case "docker":
		return s.routeDockerEndpoint(subPath, method)
	default:
		return false, nil, true
	}
}

// routeMonitorsEndpoint routes /api/monitors/* endpoints
func (s *Server) routeMonitorsEndpoint(subPath, method string) (exists bool, handler APIHandlerFunc, requireAuth bool) {
	requireAuth = true // Default: require auth
	
	if subPath == "" {
		// /api/monitors - collection operations
		exists = true
		switch method {
		case http.MethodGet:
			handler = s.apiMonitorsList
			requireAuth = false // Public endpoint
		case http.MethodPost:
			handler = s.apiMonitorsCreate
		default:
			return false, nil, true
		}
	} else if subPath == "reorder" {
		// /api/monitors/reorder
		exists = true
		if method == http.MethodPost {
			handler = s.apiMonitorsReorder
		} else {
			return false, nil, true
		}
	} else if strings.HasPrefix(subPath, "chart/") {
		// /api/monitors/chart/{id}
		exists = true
		if method == http.MethodGet {
			handler = s.apiMonitorChart
			requireAuth = false // Public endpoint
		} else {
			return false, nil, true
		}
	} else {
		// /api/monitors/{id} - item operations
		exists = true
		switch method {
		case http.MethodGet:
			handler = s.apiMonitorGet
			requireAuth = false // Public endpoint
		case http.MethodPut:
			handler = s.apiMonitorUpdate
		case http.MethodDelete:
			handler = s.apiMonitorDelete
		default:
			return false, nil, true
		}
	}
	
	return exists, handler, requireAuth
}

// sendJSONResponse sends a successful JSON response
func (s *Server) sendJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	
	if statusCode == http.StatusNoContent {
		w.WriteHeader(statusCode)
		return
	}
	
	if statusCode != http.StatusOK && statusCode != http.StatusCreated {
		w.WriteHeader(statusCode)
	} else if statusCode == http.StatusCreated {
		w.WriteHeader(statusCode)
	}
	
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			s.logger.Printf("failed to encode JSON response: %v", err)
		}
	}
}

// sendJSONError sends an error JSON response
func (s *Server) sendJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	response := APIResponse{
		Success: false,
		Error:   message,
	}
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Printf("failed to encode JSON error: %v", err)
	}
}

// ==== API: Monitor Handler Functions =========================================

// apiMonitorsList returns the list of all monitors
func (s *Server) apiMonitorsList(r *http.Request) (interface{}, int, error) {
	snapshots := s.manager.List()
	return snapshots, http.StatusOK, nil
}

// apiMonitorsCreate creates a new monitor
func (s *Server) apiMonitorsCreate(r *http.Request) (interface{}, int, error) {
	var req monitorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, http.StatusBadRequest, err
	}
	
	cfg, err := req.toConfig("")
	if err != nil {
		return nil, http.StatusBadRequest, err
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
		return nil, http.StatusBadRequest, err
	}
	
	if err := s.persistMonitors(); err != nil {
		s.logger.Printf("persist monitors after api create: %v", err)
	}
	
	return monitorCfg, http.StatusCreated, nil
}

// apiMonitorGet returns a single monitor by ID
func (s *Server) apiMonitorGet(r *http.Request) (interface{}, int, error) {
	id := strings.TrimPrefix(r.URL.Path, "/api/monitors/")
	if id == "" {
		return nil, http.StatusNotFound, http.ErrMissingFile
	}
	
	snapshot, err := s.manager.GetSnapshot(id)
	if err != nil {
		return nil, http.StatusNotFound, err
	}
	
	apiSnapshot := convertSnapshotToAPI(snapshot)
	return apiSnapshot, http.StatusOK, nil
}

// apiMonitorUpdate updates an existing monitor
func (s *Server) apiMonitorUpdate(r *http.Request) (interface{}, int, error) {
	id := strings.TrimPrefix(r.URL.Path, "/api/monitors/")
	if id == "" {
		return nil, http.StatusNotFound, http.ErrMissingFile
	}
	
	var req monitorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, http.StatusBadRequest, err
	}
	
	cfg, err := req.toConfig(id)
	if err != nil {
		return nil, http.StatusBadRequest, err
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
		return nil, http.StatusBadRequest, err
	}
	
	if err := s.persistMonitors(); err != nil {
		s.logger.Printf("persist monitors after api update: %v", err)
	}
	
	return monitorCfg, http.StatusOK, nil
}

// apiMonitorDelete deletes a monitor
func (s *Server) apiMonitorDelete(r *http.Request) (interface{}, int, error) {
	id := strings.TrimPrefix(r.URL.Path, "/api/monitors/")
	if id == "" {
		return nil, http.StatusNotFound, http.ErrMissingFile
	}
	
	if err := s.manager.RemoveMonitor(id); err != nil {
		return nil, http.StatusNotFound, err
	}
	
	// Delete from database if configured
	if s.configDB != nil {
		if err := s.configDB.DeleteMonitor(id); err != nil {
			s.logger.Printf("failed to delete monitor %s from database: %v", id, err)
			return nil, http.StatusInternalServerError, err
		}
	}
	
	if err := s.persistMonitors(); err != nil {
		s.logger.Printf("persist monitors after api delete: %v", err)
	}
	
	return nil, http.StatusNoContent, nil
}

// apiMonitorsReorder reorders monitors within and across groups
func (s *Server) apiMonitorsReorder(r *http.Request) (interface{}, int, error) {
	var multi struct {
		Groups []struct {
			GroupID int      `json:"group_id"`
			Order   []string `json:"order"`
		} `json:"groups"`
	}
	
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	
	if err := json.Unmarshal(body, &multi); err != nil || len(multi.Groups) == 0 {
		return nil, http.StatusBadRequest, err
	}
	
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
	
	return nil, http.StatusNoContent, nil
}

// apiMonitorChart returns chart data for a specific monitor
func (s *Server) apiMonitorChart(r *http.Request) (interface{}, int, error) {
	// Extract monitor ID from URL path: /api/monitors/chart/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/monitors/chart/")
	monitorID := strings.TrimSpace(path)
	
	if monitorID == "" {
		return nil, http.StatusBadRequest, http.ErrMissingFile
	}
	
	// Get monitor snapshot
	snap, err := s.manager.GetSnapshot(monitorID)
	if err != nil {
		return nil, http.StatusNotFound, err
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
	
	return chartData, http.StatusOK, nil
}

// ==== API: Notifications Routing =============================================

// routeNotificationsEndpoint routes /api/notifications/* endpoints
func (s *Server) routeNotificationsEndpoint(subPath, method string) (exists bool, handler APIHandlerFunc, requireAuth bool) {
	requireAuth = true // Default: require auth
	
	if subPath == "" {
		// /api/notifications - collection operations
		exists = true
		switch method {
		case http.MethodGet:
			handler = s.apiNotificationsList
			// Notifications may contain sensitive URLs (API keys, tokens)
			// Require authentication to access
		case http.MethodPost:
			handler = s.apiNotificationsCreate
		default:
			return false, nil, true
		}
	} else if strings.HasSuffix(subPath, "/test") {
		// /api/notifications/{id}/test
		exists = true
		if method == http.MethodPost {
			handler = s.apiNotificationTest
		} else {
			return false, nil, true
		}
	} else {
		// /api/notifications/{id} - item operations
		exists = true
		switch method {
		case http.MethodGet:
			handler = s.apiNotificationGet
			// Notifications may contain sensitive URLs (API keys, tokens)
			// Require authentication to access
		case http.MethodPut:
			handler = s.apiNotificationUpdate
		case http.MethodDelete:
			handler = s.apiNotificationDelete
		default:
			return false, nil, true
		}
	}
	
	return exists, handler, requireAuth
}

// ==== API: Notification Handler Functions ====================================

// apiNotificationsList returns the list of all notifications
func (s *Server) apiNotificationsList(r *http.Request) (interface{}, int, error) {
	return s.notifications, http.StatusOK, nil
}

// apiNotificationsCreate creates a new notification
func (s *Server) apiNotificationsCreate(r *http.Request) (interface{}, int, error) {
	var body struct {
		Name, URL string
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return nil, http.StatusBadRequest, err
	}

	name := strings.TrimSpace(body.Name)
	urlStr := normalizeShoutrrrURL(strings.TrimSpace(body.URL))
	if name == "" || urlStr == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("name and url are required")
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
			return nil, http.StatusInternalServerError, dbErr
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
	
	return n, http.StatusCreated, nil
}

// apiNotificationGet returns a single notification by ID
func (s *Server) apiNotificationGet(r *http.Request) (interface{}, int, error) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/notifications/")
	if idStr == "" {
		return nil, http.StatusNotFound, fmt.Errorf("notification not found")
	}
	
	nid, err := strconv.Atoi(idStr)
	if err != nil || nid <= 0 {
		return nil, http.StatusNotFound, fmt.Errorf("invalid notification ID")
	}
	
	for _, n := range s.notifications {
		if n.ID == nid {
			return n, http.StatusOK, nil
		}
	}
	
	return nil, http.StatusNotFound, fmt.Errorf("notification not found")
}

// apiNotificationUpdate updates an existing notification
func (s *Server) apiNotificationUpdate(r *http.Request) (interface{}, int, error) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/notifications/")
	if idStr == "" {
		return nil, http.StatusNotFound, fmt.Errorf("notification not found")
	}
	
	nid, err := strconv.Atoi(idStr)
	if err != nil || nid <= 0 {
		return nil, http.StatusNotFound, fmt.Errorf("invalid notification ID")
	}
	
	var body struct {
		Name, URL string
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return nil, http.StatusBadRequest, err
	}
	
	for i := range s.notifications {
		if s.notifications[i].ID == nid {
			s.notifications[i].Name = strings.TrimSpace(body.Name)
			s.notifications[i].URL = normalizeShoutrrrURL(strings.TrimSpace(body.URL))
			if err := s.saveConfig(); err != nil {
				s.logger.Printf("persist after api notification update: %v", err)
			}
			return s.notifications[i], http.StatusOK, nil
		}
	}
	
	return nil, http.StatusNotFound, fmt.Errorf("notification not found")
}

// apiNotificationDelete deletes a notification
func (s *Server) apiNotificationDelete(r *http.Request) (interface{}, int, error) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/notifications/")
	if idStr == "" {
		return nil, http.StatusNotFound, fmt.Errorf("notification not found")
	}
	
	nid, err := strconv.Atoi(idStr)
	if err != nil || nid <= 0 {
		return nil, http.StatusNotFound, fmt.Errorf("invalid notification ID")
	}
	
	idx := -1
	for i, n := range s.notifications {
		if n.ID == nid {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil, http.StatusNotFound, fmt.Errorf("notification not found")
	}
	
	s.notifications = append(s.notifications[:idx], s.notifications[idx+1:]...)
	
	// Clear notification references in monitors
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
	
	// Delete from database if configured
	if s.configDB != nil {
		if err := s.configDB.DeleteNotification(nid); err != nil {
			s.logger.Printf("failed to delete notification %d from database: %v", nid, err)
		}
	}
	
	if err := s.saveConfig(); err != nil {
		s.logger.Printf("persist after api notification delete: %v", err)
	}
	
	return nil, http.StatusNoContent, nil
}

// apiNotificationTest sends a test notification
func (s *Server) apiNotificationTest(r *http.Request) (interface{}, int, error) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/notifications/")
	// Expect format: {id}/test
	parts := strings.Split(strings.TrimSuffix(idStr, "/"), "/")
	if len(parts) < 2 || parts[1] != "test" {
		return nil, http.StatusNotFound, fmt.Errorf("invalid test endpoint")
	}
	
	nid, err := strconv.Atoi(parts[0])
	if err != nil || nid <= 0 {
		return nil, http.StatusNotFound, fmt.Errorf("invalid notification ID")
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
		return nil, http.StatusNotFound, fmt.Errorf("notification not found")
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
		return nil, http.StatusBadGateway, fmt.Errorf("failed to send test notification")
	}
	
	return nil, http.StatusNoContent, nil
}

// ==== API: Groups Routing ====================================================

// routeGroupsEndpoint routes /api/groups/* endpoints
func (s *Server) routeGroupsEndpoint(subPath, method string) (exists bool, handler APIHandlerFunc, requireAuth bool) {
	requireAuth = true // Default: require auth
	
	if subPath == "" {
		// /api/groups - collection operations
		exists = true
		switch method {
		case http.MethodGet:
			handler = s.apiGroupsList
			requireAuth = false // Public endpoint
		case http.MethodPost:
			handler = s.apiGroupsCreate
		default:
			return false, nil, true
		}
	} else {
		// /api/groups/{id} - item operations
		exists = true
		switch method {
		case http.MethodPut:
			handler = s.apiGroupUpdate
		case http.MethodDelete:
			handler = s.apiGroupDelete
		default:
			return false, nil, true
		}
	}
	
	return exists, handler, requireAuth
}

// ==== API: Group Handler Functions ===========================================

// apiGroupsList returns the list of all default groups
func (s *Server) apiGroupsList(r *http.Request) (interface{}, int, error) {
	// Filter to only return default groups (exclude statuspage groups)
	defaultGroups := make([]config.GroupConfig, 0)
	for _, g := range s.groups {
		if g.Type == "" || g.Type == config.GroupTypeDefault {
			defaultGroups = append(defaultGroups, g)
		}
	}
	return defaultGroups, http.StatusOK, nil
}

// apiGroupsCreate creates a new group
func (s *Server) apiGroupsCreate(r *http.Request) (interface{}, int, error) {
	var body struct {
		Name      string `json:"name"`
		Type      string `json:"type"`
		Order     int    `json:"order"`
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return nil, http.StatusBadRequest, err
	}

	name := strings.TrimSpace(body.Name)
	if name == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("name required")
	}
	
	for _, g := range s.groups {
		if g.Name == name {
			return nil, http.StatusConflict, fmt.Errorf("group exists")
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
			return nil, http.StatusInternalServerError, dbErr
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

	result := map[string]any{
		"id":    gid,
		"name":  name,
		"type":  string(groupType),
		"order": nextOrder,
	}
	return result, http.StatusCreated, nil
}

// apiGroupUpdate updates an existing group (rename or move)
func (s *Server) apiGroupUpdate(r *http.Request) (interface{}, int, error) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/groups/")
	if idStr == "" {
		return nil, http.StatusNotFound, fmt.Errorf("group not found")
	}
	
	gid, err := strconv.Atoi(idStr)
	if err != nil || gid <= 0 {
		return nil, http.StatusNotFound, fmt.Errorf("invalid group ID")
	}
	
	var body struct {
		Name string
		Move string
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return nil, http.StatusBadRequest, err
	}
	
	idx := -1
	for i, g := range s.groups {
		if g.ID == gid {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil, http.StatusNotFound, fmt.Errorf("group not found")
	}
	
	mv := strings.ToLower(strings.TrimSpace(body.Move))
	if mv == "up" || mv == "down" {
		// Build list of default groups only (exclude statuspage groups)
		defaultIndices := make([]int, 0)
		for i, g := range s.groups {
			if g.Type == "" || g.Type == config.GroupTypeDefault {
				defaultIndices = append(defaultIndices, i)
			}
		}
		
		// Sort default groups by Order
		sort.Slice(defaultIndices, func(a, b int) bool {
			return s.groups[defaultIndices[a]].Order < s.groups[defaultIndices[b]].Order
		})
		
		// Find position of target group in default groups
		posInDefaults := -1
		for pos, globalIdx := range defaultIndices {
			if s.groups[globalIdx].ID == gid {
				posInDefaults = pos
				idx = globalIdx
				break
			}
		}
		
		if posInDefaults == -1 {
			return nil, http.StatusNotFound, fmt.Errorf("group not found in default groups")
		}
		
		// Swap Order values with neighbor in default groups
		if mv == "up" && posInDefaults > 0 {
			prevIdx := defaultIndices[posInDefaults-1]
			s.groups[idx].Order, s.groups[prevIdx].Order = s.groups[prevIdx].Order, s.groups[idx].Order
		} else if mv == "down" && posInDefaults < len(defaultIndices)-1 {
			nextIdx := defaultIndices[posInDefaults+1]
			s.groups[idx].Order, s.groups[nextIdx].Order = s.groups[nextIdx].Order, s.groups[idx].Order
		}
		
		// Re-normalize to sort by new Order and reassign sequential values
		s.normalizeAndSortGroups()
		
		if err := s.saveConfig(); err != nil {
			s.logger.Printf("persist api group move: %v", err)
		}
		return nil, http.StatusNoContent, nil
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
		return nil, http.StatusNoContent, nil
	}
	
	return nil, http.StatusBadRequest, fmt.Errorf("nothing to update")
}

// apiGroupDelete deletes a group
func (s *Server) apiGroupDelete(r *http.Request) (interface{}, int, error) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/groups/")
	if idStr == "" {
		return nil, http.StatusNotFound, fmt.Errorf("group not found")
	}
	
	gid, err := strconv.Atoi(idStr)
	if err != nil || gid <= 0 {
		return nil, http.StatusNotFound, fmt.Errorf("invalid group ID")
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
		return nil, http.StatusNotFound, fmt.Errorf("group not found")
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
			// Delete from database if configured
			if s.configDB != nil {
				if err := s.configDB.DeleteMonitor(snap.Config.ID); err != nil {
					s.logger.Printf("failed to delete monitor %s from database: %v", snap.Config.ID, err)
				}
			}
		} else {
			cfg := snap.Config
			cfg.Group = ""
			cfg.GroupID = 0
			_, _ = s.manager.UpdateMonitor(cfg)
		}
	}
	
	// Delete from database if configured
	if s.configDB != nil {
		if err := s.configDB.DeleteGroup(gid); err != nil {
			s.logger.Printf("failed to delete group %d from database: %v", gid, err)
		}
	}
	
	if err := s.saveConfig(); err != nil {
		s.logger.Printf("persist api group delete: %v", err)
	}
	
	return nil, http.StatusNoContent, nil
}

// ==== API: Settings Routing ==================================================

// routeSettingsEndpoint routes /api/settings endpoint
func (s *Server) routeSettingsEndpoint(subPath, method string) (exists bool, handler APIHandlerFunc, requireAuth bool) {
	requireAuth = true // Always require auth for settings
	
	if subPath == "" {
		// /api/settings
		exists = true
		if method == http.MethodPut {
			handler = s.apiSettingsUpdate
		} else {
			return false, nil, true
		}
	} else {
		return false, nil, true
	}
	
	return exists, handler, requireAuth
}

// ==== API: Settings Handler Functions ========================================

// apiSettingsUpdate updates application settings
func (s *Server) apiSettingsUpdate(r *http.Request) (interface{}, int, error) {
	var body struct {
		MonitorDebug      bool   `json:"monitor_debug"`
		NotificationDebug bool   `json:"notification_debug"`
		ApiDebug          bool   `json:"api_debug"`
		AuthDebug         bool   `json:"auth_debug"`
		CSRFToken         string `json:"csrf_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return nil, http.StatusBadRequest, err
	}

	// Validate CSRF token from JSON body
	if !s.validateCSRFTokenFromJSON(r, body.CSRFToken) {
		return nil, http.StatusForbidden, fmt.Errorf("CSRF token validation failed")
	}

	s.monitorDebug = body.MonitorDebug
	s.notificationDebug = body.NotificationDebug
	s.apiDebug = body.ApiDebug
	s.authDebug = body.AuthDebug

	if s.manager != nil {
		s.manager.SetMonitorDebug(body.MonitorDebug)
		s.manager.SetNotificationDebug(body.NotificationDebug)
	}
	notifier.ConfigureDebugLogging(body.NotificationDebug)

	if err := s.saveConfig(); err != nil {
		s.logger.Printf("persist after settings update: %v", err)
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to save settings")
	}

	return nil, http.StatusNoContent, nil
}

// ==== API: History Routing ===================================================

// routeHistoryEndpoint routes /api/history/* endpoints
func (s *Server) routeHistoryEndpoint(subPath, method string) (exists bool, handler APIHandlerFunc, requireAuth bool) {
	requireAuth = true // Require auth for history
	
	if subPath != "" {
		// /api/history/{id}
		exists = true
		if method == http.MethodGet {
			handler = s.apiHistoryGet
		} else {
			return false, nil, true
		}
	} else {
		return false, nil, true
	}
	
	return exists, handler, requireAuth
}

// ==== API: History Handler Functions =========================================

// apiHistoryGet returns history data for a specific monitor
func (s *Server) apiHistoryGet(r *http.Request) (interface{}, int, error) {
	// Parse monitor ID from path: /api/history/{id}
	id := strings.TrimPrefix(r.URL.Path, "/api/history/")
	if id == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("monitor ID required")
	}

	snapshot, err := s.manager.GetSnapshot(id)
	if err != nil {
		return nil, http.StatusNotFound, err
	}

	// Convert history to API format
	apiHistory := make([]APICheckResult, len(snapshot.History))
	for i, result := range snapshot.History {
		apiHistory[i] = convertCheckResultToAPI(result)
	}

	return apiHistory, http.StatusOK, nil
}

// ==== API: Status Pages Routing ==============================================

// routeStatusPagesEndpoint routes /api/statuspages/* endpoints
func (s *Server) routeStatusPagesEndpoint(subPath, method string) (exists bool, handler APIHandlerFunc, requireAuth bool) {
	requireAuth = true // Always require auth for status pages
	
	if subPath == "" {
		// /api/statuspages - collection operations
		exists = true
		switch method {
		case http.MethodGet:
			handler = s.apiStatusPagesList
		case http.MethodPost:
			handler = s.apiStatusPagesCreate
		default:
			return false, nil, true
		}
	} else {
		// /api/statuspages/{id} - item operations
		exists = true
		switch method {
		case http.MethodGet:
			handler = s.apiStatusPageGet
		case http.MethodPut:
			handler = s.apiStatusPageUpdate
		case http.MethodDelete:
			handler = s.apiStatusPageDelete
		default:
			return false, nil, true
		}
	}
	
	return exists, handler, requireAuth
}

// ==== API: Status Page Handler Functions =====================================

// apiStatusPagesList returns the list of all status pages
func (s *Server) apiStatusPagesList(r *http.Request) (interface{}, int, error) {
	return s.statusPages, http.StatusOK, nil
}

// apiStatusPageGet returns a single status page by ID
func (s *Server) apiStatusPageGet(r *http.Request) (interface{}, int, error) {
	path := strings.TrimPrefix(r.URL.Path, "/api/statuspages/")
	path = strings.Trim(path, "/")
	
	id, err := strconv.Atoi(path)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid status page ID")
	}

	for _, sp := range s.statusPages {
		if sp.ID == id {
			return sp, http.StatusOK, nil
		}
	}

	return nil, http.StatusNotFound, fmt.Errorf("status page not found")
}

// apiStatusPagesCreate creates a new status page
func (s *Server) apiStatusPagesCreate(r *http.Request) (interface{}, int, error) {
	var body struct {
		Name      string `json:"name"`
		Slug      string `json:"slug"`
		Active    bool   `json:"active"`
		CSRFToken string `json:"csrf_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return nil, http.StatusBadRequest, err
	}

	if !s.validateCSRFTokenFromJSON(r, body.CSRFToken) {
		return nil, http.StatusForbidden, fmt.Errorf("CSRF token validation failed")
	}

	if body.Name == "" || body.Slug == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("name and slug are required")
	}

	// Check for duplicate slug
	for _, sp := range s.statusPages {
		if sp.Slug == body.Slug {
			return nil, http.StatusConflict, fmt.Errorf("slug already exists")
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
			return nil, http.StatusInternalServerError, fmt.Errorf("failed to create status page")
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

	return newPage, http.StatusCreated, nil
}

// apiStatusPageUpdate updates an existing status page
func (s *Server) apiStatusPageUpdate(r *http.Request) (interface{}, int, error) {
	path := strings.TrimPrefix(r.URL.Path, "/api/statuspages/")
	path = strings.TrimSuffix(path, "/")
	id, err := strconv.Atoi(path)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid status page ID")
	}

	var body struct {
		Name      string                           `json:"name"`
		Slug      string                           `json:"slug"`
		Active    bool                             `json:"active"`
		Monitors  []config.StatusPageMonitorConfig `json:"monitors"`
		CSRFToken string                           `json:"csrf_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return nil, http.StatusBadRequest, err
	}

	if !s.validateCSRFTokenFromJSON(r, body.CSRFToken) {
		return nil, http.StatusForbidden, fmt.Errorf("CSRF token validation failed")
	}

	// Find and update status page
	found := false
	for i := range s.statusPages {
		if s.statusPages[i].ID == id {
			// Check for slug conflict with other pages
			if body.Slug != s.statusPages[i].Slug {
				for j := range s.statusPages {
					if i != j && s.statusPages[j].Slug == body.Slug {
						return nil, http.StatusConflict, fmt.Errorf("slug already exists")
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
		return nil, http.StatusNotFound, fmt.Errorf("status page not found")
	}

	if err := s.saveConfig(); err != nil {
		s.logger.Printf("Failed to save config after updating status page: %v", err)
	}

	return map[string]bool{"success": true}, http.StatusOK, nil
}

// apiStatusPageDelete deletes a status page
func (s *Server) apiStatusPageDelete(r *http.Request) (interface{}, int, error) {
	path := strings.TrimPrefix(r.URL.Path, "/api/statuspages/")
	path = strings.TrimSuffix(path, "/")
	id, err := strconv.Atoi(path)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid status page ID")
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
		return nil, http.StatusNotFound, fmt.Errorf("status page not found")
	}

	if err := s.saveConfig(); err != nil {
		s.logger.Printf("Failed to save config after deleting status page: %v", err)
	}

	return map[string]bool{"success": true}, http.StatusOK, nil
}

// ==== API: Users Routing ======================================================

// routeUsersEndpoint routes /api/users/* endpoints
func (s *Server) routeUsersEndpoint(subPath, method string) (exists bool, handler APIHandlerFunc, requireAuth bool) {
	requireAuth = true // Always require auth for users
	
	// Check for API keys sub-endpoints first
	if strings.HasPrefix(subPath, "apikeys") {
		return s.routeUserAPIKeysEndpoint(subPath, method)
	}
	
	// Check for change-password endpoint
	if subPath == "change-password" {
		exists = true
		if method == http.MethodPost {
			handler = s.apiUserChangePassword
		} else {
			return false, nil, true
		}
		return exists, handler, requireAuth
	}
	
	if subPath == "" {
		// /api/users - collection operations
		exists = true
		switch method {
		case http.MethodGet:
			handler = s.apiUsersList
		case http.MethodPost:
			handler = s.apiUsersCreate
		default:
			return false, nil, true
		}
	} else {
		// /api/users/{id} - item operations
		exists = true
		switch method {
		case http.MethodGet:
			handler = s.apiUserGet
		case http.MethodPut:
			handler = s.apiUserUpdate
		case http.MethodDelete:
			handler = s.apiUserDelete
		default:
			return false, nil, true
		}
	}
	
	return exists, handler, requireAuth
}

// routeUserAPIKeysEndpoint routes /api/users/apikeys/* endpoints
func (s *Server) routeUserAPIKeysEndpoint(subPath, method string) (exists bool, handler APIHandlerFunc, requireAuth bool) {
	requireAuth = true // Always require auth for API keys
	
	// Remove "apikeys" prefix
	rest := strings.TrimPrefix(subPath, "apikeys")
	rest = strings.Trim(rest, "/")
	
	if rest == "" {
		// /api/users/apikeys - collection operations
		exists = true
		if method == http.MethodGet {
			handler = s.apiAPIKeysList
		} else {
			return false, nil, true
		}
	} else if rest == "generate" {
		// /api/users/apikeys/generate
		exists = true
		if method == http.MethodPost {
			handler = s.apiAPIKeysGenerate
		} else {
			return false, nil, true
		}
	} else if rest == "revoke" {
		// /api/users/apikeys/revoke
		exists = true
		if method == http.MethodDelete {
			handler = s.apiAPIKeysRevoke
		} else {
			return false, nil, true
		}
	} else {
		return false, nil, true
	}
	
	return exists, handler, requireAuth
}

// ==== API: User Handler Functions ============================================

// UserResponse represents a user without sensitive data
type UserResponse struct {
	ID        int               `json:"id"`
	Username  string            `json:"username"`
	Role      database.UserRole `json:"role"`
	Enabled   bool              `json:"enabled"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// apiUsersList returns all users (admin only)
func (s *Server) apiUsersList(r *http.Request) (interface{}, int, error) {
	// Only allow access if using database authentication
	if !s.isUsingDatabaseAuth() {
		return nil, http.StatusBadRequest, fmt.Errorf("user management only available with database authentication")
	}

	// Check if current user has admin permissions
	currentUser := s.getCurrentUser(r)
	if currentUser == nil || currentUser.Role != database.UserRoleAdmin {
		return nil, http.StatusForbidden, fmt.Errorf("access denied - admin role required")
	}

	users, err := s.configDB.GetAllUsers()
	if err != nil {
		s.logger.Printf("Failed to get users: %v", err)
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to get users")
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

	return response, http.StatusOK, nil
}

// apiUserGet returns a single user (admin only)
func (s *Server) apiUserGet(r *http.Request) (interface{}, int, error) {
	// Only allow access if using database authentication
	if !s.isUsingDatabaseAuth() {
		return nil, http.StatusBadRequest, fmt.Errorf("user management only available with database authentication")
	}

	// Check if current user has admin permissions
	currentUser := s.getCurrentUser(r)
	if currentUser == nil || currentUser.Role != database.UserRoleAdmin {
		return nil, http.StatusForbidden, fmt.Errorf("access denied - admin role required")
	}

	userIDStr := strings.TrimPrefix(r.URL.Path, "/api/users/")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid user ID")
	}

	user, err := s.configDB.GetUser(userID)
	if err != nil {
		return nil, http.StatusNotFound, fmt.Errorf("user not found")
	}

	response := UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Role:      user.Role,
		Enabled:   user.Enabled,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	return response, http.StatusOK, nil
}

// apiUsersCreate creates a new user (admin only)
func (s *Server) apiUsersCreate(r *http.Request) (interface{}, int, error) {
	// Only allow access if using database authentication
	if !s.isUsingDatabaseAuth() {
		return nil, http.StatusBadRequest, fmt.Errorf("user management only available with database authentication")
	}

	// Check if current user has admin permissions
	currentUser := s.getCurrentUser(r)
	if currentUser == nil || currentUser.Role != database.UserRoleAdmin {
		return nil, http.StatusForbidden, fmt.Errorf("access denied - admin role required")
	}

	var req struct {
		Username string            `json:"username"`
		Password string            `json:"password"`
		Role     database.UserRole `json:"role"`
		Enabled  bool              `json:"enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, http.StatusBadRequest, err
	}

	// Validate input
	if req.Username == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("username is required")
	}
	if req.Password == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("password is required")
	}

	// Validate username format
	if err := validateUsername(req.Username); err != nil {
		return nil, http.StatusBadRequest, err
	}

	// Validate password complexity
	if err := validatePassword(req.Password); err != nil {
		return nil, http.StatusBadRequest, err
	}

	if req.Role == "" {
		req.Role = database.UserRoleReadOnly // Default role
	}

	// Validate role
	if req.Role != database.UserRoleReadOnly && req.Role != database.UserRoleWrite && req.Role != database.UserRoleAdmin {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid role")
	}

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Printf("Failed to hash password: %v", err)
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to process password")
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
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to create user")
	}

	response := UserResponse{
		ID:        savedUser.ID,
		Username:  savedUser.Username,
		Role:      savedUser.Role,
		Enabled:   savedUser.Enabled,
		CreatedAt: savedUser.CreatedAt,
		UpdatedAt: savedUser.UpdatedAt,
	}

	return response, http.StatusCreated, nil
}

// apiUserUpdate updates an existing user (admin only)
func (s *Server) apiUserUpdate(r *http.Request) (interface{}, int, error) {
	// Only allow access if using database authentication
	if !s.isUsingDatabaseAuth() {
		return nil, http.StatusBadRequest, fmt.Errorf("user management only available with database authentication")
	}

	// Check if current user has admin permissions
	currentUser := s.getCurrentUser(r)
	if currentUser == nil || currentUser.Role != database.UserRoleAdmin {
		return nil, http.StatusForbidden, fmt.Errorf("access denied - admin role required")
	}

	userIDStr := strings.TrimPrefix(r.URL.Path, "/api/users/")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid user ID")
	}

	// Get existing user
	existingUser, err := s.configDB.GetUser(userID)
	if err != nil {
		return nil, http.StatusNotFound, fmt.Errorf("user not found")
	}

	var req struct {
		Username string            `json:"username"`
		Password string            `json:"password,omitempty"` // Optional for updates
		Role     database.UserRole `json:"role"`
		Enabled  bool              `json:"enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, http.StatusBadRequest, err
	}

	// Validate input
	if req.Username == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("username is required")
	}

	// Validate username format if changed
	if req.Username != existingUser.Username {
		if err := validateUsername(req.Username); err != nil {
			return nil, http.StatusBadRequest, err
		}
	}

	// Validate role
	if req.Role != database.UserRoleReadOnly && req.Role != database.UserRoleWrite && req.Role != database.UserRoleAdmin {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid role")
	}

	// Update user data
	existingUser.Username = req.Username
	existingUser.Role = req.Role
	existingUser.Enabled = req.Enabled

	// Update password if provided
	if req.Password != "" {
		// Validate password complexity
		if err := validatePassword(req.Password); err != nil {
			return nil, http.StatusBadRequest, err
		}
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			s.logger.Printf("Failed to hash password: %v", err)
			return nil, http.StatusInternalServerError, fmt.Errorf("failed to process password")
		}
		existingUser.PasswordHash = string(passwordHash)
	}

	// Save updated user
	savedUser, err := s.configDB.SaveUser(*existingUser)
	if err != nil {
		s.logger.Printf("Failed to update user: %v", err)
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to update user")
	}

	response := UserResponse{
		ID:        savedUser.ID,
		Username:  savedUser.Username,
		Role:      savedUser.Role,
		Enabled:   savedUser.Enabled,
		CreatedAt: savedUser.CreatedAt,
		UpdatedAt: savedUser.UpdatedAt,
	}

	return response, http.StatusOK, nil
}

// apiUserDelete deletes a user (admin only)
func (s *Server) apiUserDelete(r *http.Request) (interface{}, int, error) {
	// Only allow access if using database authentication
	if !s.isUsingDatabaseAuth() {
		return nil, http.StatusBadRequest, fmt.Errorf("user management only available with database authentication")
	}

	// Check if current user has admin permissions
	currentUser := s.getCurrentUser(r)
	if currentUser == nil || currentUser.Role != database.UserRoleAdmin {
		return nil, http.StatusForbidden, fmt.Errorf("access denied - admin role required")
	}

	userIDStr := strings.TrimPrefix(r.URL.Path, "/api/users/")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid user ID")
	}

	// Prevent deleting the current user
	if currentUser != nil && currentUser.ID == userID {
		return nil, http.StatusBadRequest, fmt.Errorf("cannot delete current user")
	}

	// Check if user exists
	_, err = s.configDB.GetUser(userID)
	if err != nil {
		return nil, http.StatusNotFound, fmt.Errorf("user not found")
	}

	// Delete user
	if err := s.configDB.DeleteUser(userID); err != nil {
		s.logger.Printf("Failed to delete user: %v", err)
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to delete user")
	}

	return map[string]bool{"success": true}, http.StatusOK, nil
}

// apiUserChangePassword allows a user to change their own password
func (s *Server) apiUserChangePassword(r *http.Request) (interface{}, int, error) {
	// Only allow access if using database authentication
	if !s.isUsingDatabaseAuth() {
		return nil, http.StatusBadRequest, fmt.Errorf("password change only available with database authentication")
	}

	// Get current user
	currentUser := s.getCurrentUser(r)
	if currentUser == nil {
		return nil, http.StatusUnauthorized, fmt.Errorf("authentication required")
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid request body")
	}

	// Validate input
	if req.CurrentPassword == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("current password is required")
	}
	if req.NewPassword == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("new password is required")
	}

	// Get user from database to verify current password
	user, err := s.configDB.GetUser(currentUser.ID)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to get user")
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		return nil, http.StatusUnauthorized, fmt.Errorf("current password is incorrect")
	}

	// Validate new password complexity
	if err := validatePassword(req.NewPassword); err != nil {
		return nil, http.StatusBadRequest, err
	}

	// Hash new password
	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Printf("Failed to hash new password: %v", err)
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to process new password")
	}

	// Update password in database
	user.PasswordHash = string(newPasswordHash)
	_, err = s.configDB.SaveUser(*user)
	if err != nil {
		s.logger.Printf("Failed to update password: %v", err)
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to update password")
	}

	return map[string]bool{"success": true}, http.StatusOK, nil
}

// ==== API: API Keys Handler Functions ========================================

// APIKeyResponse represents an API key without sensitive data
type APIKeyResponse struct {
	ID         int       `json:"id"`
	Name       string    `json:"name"`
	Selector   string    `json:"selector"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// apiAPIKeysList lists all API keys for the current user
func (s *Server) apiAPIKeysList(r *http.Request) (interface{}, int, error) {
	// Get current user
	currentUser := s.getCurrentUser(r)
	if currentUser == nil {
		return nil, http.StatusUnauthorized, fmt.Errorf("authentication required")
	}

	// Get all API keys for user
	keys, err := s.configDB.GetAPIKeysByUser(currentUser.ID)
	if err != nil {
		s.logger.Printf("Failed to get API keys: %v", err)
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to get API keys")
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

	return map[string]interface{}{
		"success": true,
		"keys":    response,
	}, http.StatusOK, nil
}

// apiAPIKeysGenerate generates a new API key for the current user
func (s *Server) apiAPIKeysGenerate(r *http.Request) (interface{}, int, error) {
	var req struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid request body")
	}

	if req.Name == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("name is required")
	}

	// Get current user
	currentUser := s.getCurrentUser(r)
	if currentUser == nil {
		return nil, http.StatusUnauthorized, fmt.Errorf("authentication required")
	}

	// Generate selector (16 bytes = 32 hex chars)
	selectorBytes := make([]byte, 16)
	if _, err := rand.Read(selectorBytes); err != nil {
		s.logger.Printf("Failed to generate selector: %v", err)
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to generate API key")
	}
	selector := hex.EncodeToString(selectorBytes)

	// Generate token (32 bytes = 64 hex chars)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		s.logger.Printf("Failed to generate token: %v", err)
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to generate API key")
	}
	token := hex.EncodeToString(tokenBytes)

	// Hash the token
	tokenHash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Printf("Failed to hash token: %v", err)
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to hash API key")
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
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to save API key")
	}

	// Construct full API key (format: upt_selector:token)
	fullAPIKey := fmt.Sprintf("upt_%s:%s", selector, token)

	s.logger.Printf("Generated API key '%s' for user %s (ID: %d)", req.Name, currentUser.Username, currentUser.ID)

	return map[string]interface{}{
		"success": true,
		"id":      savedKey.ID,
		"api_key": fullAPIKey,
		"message": "API key generated successfully. Please save it securely as it won't be shown again.",
	}, http.StatusOK, nil
}

// apiAPIKeysRevoke revokes an API key by ID
func (s *Server) apiAPIKeysRevoke(r *http.Request) (interface{}, int, error) {
	var req struct {
		ID int `json:"id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid request body")
	}

	// Get current user
	currentUser := s.getCurrentUser(r)
	if currentUser == nil {
		return nil, http.StatusUnauthorized, fmt.Errorf("authentication required")
	}

	// Verify ownership by getting all keys for user and finding by ID
	keys, err := s.configDB.GetAPIKeysByUser(currentUser.ID)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to get API keys")
	}

	found := false
	for _, key := range keys {
		if key.ID == req.ID {
			found = true
			break
		}
	}

	if !found {
		return nil, http.StatusNotFound, fmt.Errorf("API key not found or access denied")
	}

	// Delete API key
	if err := s.configDB.DeleteAPIKey(req.ID); err != nil {
		s.logger.Printf("Failed to revoke API key: %v", err)
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to revoke API key")
	}

	s.logger.Printf("Revoked API key ID %d for user %s", req.ID, currentUser.Username)

	return map[string]interface{}{
		"success": true,
		"message": "API key revoked successfully",
	}, http.StatusOK, nil
}

// ==== API: Public Status Routing =============================================

// routePublicEndpoint routes /api/public/* endpoints
func (s *Server) routePublicEndpoint(subPath, method string) (exists bool, handler APIHandlerFunc, requireAuth bool) {
	requireAuth = false // Public endpoints don't require auth
	
	// Check for /api/public/status/* endpoints
	if strings.HasPrefix(subPath, "status/") {
		exists = true
		if method == http.MethodGet {
			handler = s.apiPublicStatus
		} else {
			return false, nil, false
		}
	} else {
		return false, nil, false
	}
	
	return exists, handler, requireAuth
}

// ==== API: Public Status Handler Functions ===================================

// PublicGroupView represents a group in the public status page
type PublicGroupView struct {
	ID       int                  `json:"id"`
	Name     string               `json:"name"`
	Monitors []PublicMonitorView  `json:"monitors"`
}

// PublicMonitorView represents a monitor in the public status page
type PublicMonitorView struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Status       string    `json:"status"`
	LastChecked  time.Time `json:"last_checked"`
	LastLatency  int64     `json:"last_latency_ms"`
	LastChange   time.Time `json:"last_change"`
	LastDownTime time.Time `json:"last_down_time,omitempty"`
}

// apiPublicStatus returns JSON data for a public status page
func (s *Server) apiPublicStatus(r *http.Request) (interface{}, int, error) {
	// Extract slug from URL
	slug := strings.TrimPrefix(r.URL.Path, "/api/public/status/")
	slug = strings.TrimSuffix(slug, "/")

	if slug == "" {
		return nil, http.StatusNotFound, fmt.Errorf("status page not found")
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
		return nil, http.StatusNotFound, fmt.Errorf("status page not found")
	}

	if !statusPage.Active {
		return nil, http.StatusNotFound, fmt.Errorf("status page not active")
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

	return response, http.StatusOK, nil
}

// ==== API: Status Routing ====================================================

// routeStatusEndpoint routes /api/status endpoint
func (s *Server) routeStatusEndpoint(subPath, method string) (exists bool, handler APIHandlerFunc, requireAuth bool) {
	requireAuth = true // Require auth for status
	
	if subPath == "" && method == http.MethodGet {
		exists = true
		handler = s.apiStatus
	} else {
		return false, nil, true
	}
	
	return exists, handler, requireAuth
}

// ==== API: Status Handler Functions ==========================================

// apiStatus returns status information for all monitors
func (s *Server) apiStatus(r *http.Request) (interface{}, int, error) {
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
	
	return response, http.StatusOK, nil
}

// ==== API: Memory Routing ====================================================

// routeMemoryEndpoint routes /api/memory endpoint
func (s *Server) routeMemoryEndpoint(subPath, method string) (exists bool, handler APIHandlerFunc, requireAuth bool) {
	requireAuth = true // Require auth for memory stats
	
	if subPath == "" && method == http.MethodGet {
		exists = true
		handler = s.apiMemory
	} else {
		return false, nil, true
	}
	
	return exists, handler, requireAuth
}

// ==== API: Memory Handler Functions ==========================================

// apiMemory returns memory usage statistics
func (s *Server) apiMemory(r *http.Request) (interface{}, int, error) {
	memoryUsage := s.manager.GetMemoryUsage()
	return memoryUsage, http.StatusOK, nil
}

// ==== API: Docker Routing ====================================================

// routeDockerEndpoint routes /api/docker/* endpoints
func (s *Server) routeDockerEndpoint(subPath, method string) (exists bool, handler APIHandlerFunc, requireAuth bool) {
	requireAuth = true // Require auth for Docker API
	
	if subPath == "containers" && method == http.MethodGet {
		exists = true
		handler = s.apiDockerContainers
	} else {
		return false, nil, true
	}
	
	return exists, handler, requireAuth
}

// ==== API: Docker Handler Functions ==========================================

// apiDockerContainers returns a list of Docker containers
func (s *Server) apiDockerContainers(r *http.Request) (interface{}, int, error) {
	containers, err := listDockerContainers()
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to list Docker containers: %w", err)
	}
	return containers, http.StatusOK, nil
}
