package api

import (
	"crypto/x509"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/auth"
	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func (s *Server) telemetryRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/agent/telemetry", s.node(func(w http.ResponseWriter, r *http.Request, cert *x509.Certificate) {
		data, err := body(w, r, protocol.MaxTelemetryBatchBytes)
		if err != nil {
			problemCode(w, 400, "telemetry_invalid", "invalid telemetry request size")
			return
		}
		batch, err := protocol.DecodeTelemetryBatch(data)
		if err != nil {
			problemCode(w, 400, "telemetry_invalid", "invalid telemetry schema or sample")
			return
		}
		ack, err := s.Store.SubmitTelemetry(r.Context(), cert, batch)
		reply(w, ack, err)
	}))
	mux.HandleFunc("GET /v1/nodes/{id}/telemetry", s.admin(false, func(w http.ResponseWriter, r *http.Request, u auth.User) {
		values, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			problem(w, 400, "invalid telemetry query")
			return
		}
		for name, vals := range values {
			if len(vals) != 1 {
				problem(w, 400, "duplicate telemetry query parameter")
				return
			}
			switch name {
			case "from", "to", "limit", "cursor":
			default:
				problem(w, 400, "unknown telemetry query parameter")
				return
			}
		}
		now := time.Now().Unix()
		q := database.TelemetryQuery{From: now - 86400, To: now, Limit: 500, Cursor: values.Get("cursor")}
		if q.Cursor != "" && (!values.Has("from") || !values.Has("to")) {
			problem(w, 400, "pagination requires fixed from and to values")
			return
		}
		for name, dest := range map[string]*int64{"from": &q.From, "to": &q.To} {
			if values.Has(name) {
				*dest, err = strconv.ParseInt(values.Get(name), 10, 64)
				if err != nil {
					problem(w, 400, "invalid telemetry time range")
					return
				}
			}
		}
		if values.Has("limit") {
			q.Limit, err = strconv.Atoi(values.Get("limit"))
			if err != nil {
				problem(w, 400, "invalid telemetry limit")
				return
			}
		}
		if q.Validate(r.PathValue("id")) != nil {
			problem(w, 400, "invalid telemetry range or cursor")
			return
		}
		page, err := s.Store.QueryTelemetry(r.Context(), r.PathValue("id"), q)
		reply(w, page, err)
	}))
}
