package console

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func (s *Server) observationManagementRoutes(mux *http.ServeMux) {
	wrap := func(f func(http.ResponseWriter, *http.Request, database.ConsoleUser, session)) http.HandlerFunc {
		return s.authorized(true, f)
	}
	mux.HandleFunc("GET /v1/console/admin/agents/{id}/capabilities", wrap(func(w http.ResponseWriter, r *http.Request, _ database.ConsoleUser, _ session) {
		if !identity.Valid(r.PathValue("id")) {
			problem(w, 404, "not_found")
			return
		}
		value, err := s.store.Capabilities(r.Context(), r.PathValue("id"))
		if err != nil {
			storeProblem(w, err)
			return
		}
		reply(w, value)
	}))
	mux.HandleFunc("POST /v1/console/admin/agents/{id}/tags", wrap(func(w http.ResponseWriter, r *http.Request, u database.ConsoleUser, _ session) {
		var body struct {
			Tags []string `json:"tags"`
		}
		if !decode(w, r, &body, "tags") {
			return
		}
		if !protocol.ValidNodeTags(body.Tags) {
			problem(w, 400, "invalid_request")
			return
		}
		if err := s.store.SetNodeTags(r.Context(), "web:"+u.ID, r.PathValue("id"), body.Tags); err != nil {
			storeProblem(w, err)
			return
		}
		reply(w, struct{}{})
	}))
	mux.HandleFunc("POST /v1/console/admin/agents/{id}/revoke", wrap(func(w http.ResponseWriter, r *http.Request, u database.ConsoleUser, _ session) {
		var body struct {
			Confirm string `json:"confirm_node_id"`
		}
		if !decode(w, r, &body, "confirm_node_id") {
			return
		}
		if !identity.Valid(r.PathValue("id")) || body.Confirm != r.PathValue("id") {
			problem(w, 400, "invalid_request")
			return
		}
		if err := s.store.RevokeNode(r.Context(), "web:"+u.ID, r.PathValue("id")); err != nil {
			storeProblem(w, err)
			return
		}
		reply(w, struct{}{})
	}))
	mux.HandleFunc("GET /v1/console/admin/diagnostic-profiles", wrap(func(w http.ResponseWriter, r *http.Request, _ database.ConsoleUser, _ session) {
		if r.URL.RawQuery != "" {
			problem(w, 400, "invalid_request")
			return
		}
		reply(w, protocol.DiagnosticProfiles())
	}))
	mux.HandleFunc("POST /v1/console/admin/diagnostics", wrap(func(w http.ResponseWriter, r *http.Request, u database.ConsoleUser, _ session) {
		var request protocol.DiagnosticRequest
		if !decode(w, r, &request, "node_ids", "profile_id", "resource_id", "ttl_seconds", "execution_timeout_ms") {
			return
		}
		raw, err := json.Marshal(request)
		if err == nil {
			_, err = protocol.DecodeDiagnosticRequest(raw)
		}
		if err != nil {
			problem(w, 400, "invalid_request")
			return
		}
		out, err := s.store.CreateDiagnosticBatch(r.Context(), "web:"+u.ID, request)
		if errors.Is(err, database.ErrNodeDisabled) {
			problem(w, 409, "node_disabled")
			return
		}
		if errors.Is(err, database.ErrConflict) {
			problem(w, 409, "state_conflict")
			return
		}
		if err != nil {
			storeProblem(w, err)
			return
		}
		reply(w, out)
	}))
	mux.HandleFunc("GET /v1/console/admin/diagnostics/{id}", wrap(func(w http.ResponseWriter, r *http.Request, _ database.ConsoleUser, _ session) {
		if !identity.Valid(r.PathValue("id")) {
			problem(w, 404, "not_found")
			return
		}
		out, err := s.store.DiagnosticBatch(r.Context(), r.PathValue("id"))
		if err != nil {
			storeProblem(w, err)
			return
		}
		reply(w, out)
	}))
	mux.HandleFunc("POST /v1/console/admin/tasks/{id}/cancel", wrap(func(w http.ResponseWriter, r *http.Request, u database.ConsoleUser, _ session) {
		if !identity.Valid(r.PathValue("id")) {
			problem(w, 404, "not_found")
			return
		}
		if !decode(w, r, &struct{}{}) {
			return
		}
		err := s.store.CancelTask(r.Context(), "web:"+u.ID, r.PathValue("id"))
		if errors.Is(err, database.ErrConflict) {
			problem(w, 409, "state_conflict")
			return
		}
		if err != nil {
			storeProblem(w, err)
			return
		}
		reply(w, struct{}{})
	}))
	mux.HandleFunc("GET /v1/console/admin/alert-rules", wrap(func(w http.ResponseWriter, r *http.Request, _ database.ConsoleUser, _ session) {
		if r.URL.RawQuery != "" {
			problem(w, 400, "invalid_request")
			return
		}
		out, err := s.store.ListAlertRules(r.Context())
		if err != nil {
			storeProblem(w, err)
			return
		}
		reply(w, out)
	}))
	mux.HandleFunc("POST /v1/console/admin/alert-rules", wrap(func(w http.ResponseWriter, r *http.Request, u database.ConsoleUser, _ session) {
		var rule database.AlertRule
		if !decode(w, r, &rule, "id", "metric", "severity", "threshold", "for_seconds", "recovery_seconds", "enabled") {
			return
		}
		if rule.Validate() != nil {
			problem(w, 400, "invalid_request")
			return
		}
		if err := s.store.PutAlertRule(r.Context(), "web:"+u.ID, rule); err != nil {
			storeProblem(w, err)
			return
		}
		reply(w, struct{}{})
	}))
	mux.HandleFunc("GET /v1/console/admin/alerts", wrap(func(w http.ResponseWriter, r *http.Request, _ database.ConsoleUser, _ session) {
		if !listParams(w, r, "node_id", "status") {
			return
		}
		limit, ok := observationLimit(w, r)
		if !ok {
			return
		}
		q := database.AlertQuery{NodeID: r.URL.Query().Get("node_id"), Status: r.URL.Query().Get("status"), Cursor: r.URL.Query().Get("cursor"), Limit: limit}
		if q.Validate() != nil {
			problem(w, 400, "invalid_request")
			return
		}
		out, err := s.store.QueryAlerts(r.Context(), q)
		if err != nil {
			storeProblem(w, err)
			return
		}
		reply(w, out)
	}))
	mux.HandleFunc("GET /v1/console/admin/alert-events", wrap(func(w http.ResponseWriter, r *http.Request, _ database.ConsoleUser, _ session) {
		if !listParams(w, r, "node_id", "alert_id", "after") {
			return
		}
		if r.URL.Query().Has("cursor") {
			problem(w, 400, "invalid_request")
			return
		}
		limit, ok := observationLimit(w, r)
		if !ok {
			return
		}
		after := int64(0)
		var err error
		if raw := r.URL.Query().Get("after"); raw != "" {
			after, err = strconv.ParseInt(raw, 10, 64)
			if err != nil || after < 0 {
				problem(w, 400, "invalid_request")
				return
			}
		}
		q := database.AlertEventQuery{NodeID: r.URL.Query().Get("node_id"), AlertID: r.URL.Query().Get("alert_id"), After: after, Limit: limit}
		if q.Validate() != nil {
			problem(w, 400, "invalid_request")
			return
		}
		out, err := s.store.QueryAlertEvents(r.Context(), q)
		if err != nil {
			storeProblem(w, err)
			return
		}
		reply(w, out)
	}))
}
func observationLimit(w http.ResponseWriter, r *http.Request) (int, bool) {
	limit := 50
	var err error
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
	}
	if err != nil || limit < 1 || limit > 200 {
		problem(w, 400, "invalid_request")
		return 0, false
	}
	return limit, true
}
