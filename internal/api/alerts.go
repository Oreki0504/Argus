package api

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/Oreki0504/Argus-C2/internal/auth"
	"github.com/Oreki0504/Argus-C2/internal/database"
)

func alertQueryValues(w http.ResponseWriter, r *http.Request, allowed ...string) (url.Values, bool) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		problem(w, 400, "invalid alert query")
		return nil, false
	}
	for key, items := range values {
		found := false
		for _, name := range allowed {
			if key == name {
				found = true
			}
		}
		if !found || len(items) != 1 {
			problem(w, 400, "unknown or duplicate alert query parameter")
			return nil, false
		}
	}
	return values, true
}

func (s *Server) alertRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/alert-rules", s.admin(false, func(w http.ResponseWriter, r *http.Request, u auth.User) {
		if _, ok := alertQueryValues(w, r); !ok {
			return
		}
		items, err := s.Store.ListAlertRules(r.Context())
		reply(w, items, err)
	}))
	mux.HandleFunc("PUT /v1/alert-rules/{id}", s.admin(true, func(w http.ResponseWriter, r *http.Request, u auth.User) {
		var rule database.AlertRule
		if !decode(w, r, &rule, 2048, "id", "metric", "severity", "threshold", "for_seconds", "recovery_seconds", "enabled") {
			return
		}
		if rule.ID != r.PathValue("id") || rule.Validate() != nil {
			problem(w, 400, "invalid alert rule")
			return
		}
		reply(w, struct{}{}, s.Store.PutAlertRule(r.Context(), u.Name, rule))
	}))
	mux.HandleFunc("GET /v1/alerts", s.admin(false, func(w http.ResponseWriter, r *http.Request, u auth.User) {
		values, ok := alertQueryValues(w, r, "node_id", "status", "cursor", "limit")
		if !ok {
			return
		}
		q := database.AlertQuery{NodeID: values.Get("node_id"), Status: values.Get("status"), Cursor: values.Get("cursor"), Limit: 50}
		var err error
		if values.Has("limit") {
			q.Limit, err = strconv.Atoi(values.Get("limit"))
			if err != nil {
				problem(w, 400, "invalid alert limit")
				return
			}
		}
		if q.Validate() != nil {
			problem(w, 400, "invalid alert query")
			return
		}
		page, err := s.Store.QueryAlerts(r.Context(), q)
		reply(w, page, err)
	}))
	mux.HandleFunc("GET /v1/alert-events", s.admin(false, func(w http.ResponseWriter, r *http.Request, u auth.User) {
		values, ok := alertQueryValues(w, r, "node_id", "alert_id", "after", "limit")
		if !ok {
			return
		}
		q := database.AlertEventQuery{NodeID: values.Get("node_id"), AlertID: values.Get("alert_id"), Limit: 100}
		var err error
		if values.Has("limit") {
			q.Limit, err = strconv.Atoi(values.Get("limit"))
			if err != nil {
				problem(w, 400, "invalid event limit")
				return
			}
		}
		if values.Has("after") {
			q.After, err = strconv.ParseInt(values.Get("after"), 10, 64)
			if err != nil {
				problem(w, 400, "invalid event cursor")
				return
			}
		}
		if q.Validate() != nil {
			problem(w, 400, "invalid event query")
			return
		}
		items, err := s.Store.QueryAlertEvents(r.Context(), q)
		reply(w, items, err)
	}))
}
