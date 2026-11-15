package api

import (
	"net/http"

	"github.com/Oreki0504/Argus-C2/internal/auth"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func (s *Server) diagnosticRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/diagnostic-profiles", s.admin(false, func(w http.ResponseWriter, r *http.Request, u auth.User) {
		reply(w, protocol.DiagnosticProfiles(), nil)
	}))
	mux.HandleFunc("POST /v1/diagnostics", s.admin(true, func(w http.ResponseWriter, r *http.Request, u auth.User) {
		data, err := body(w, r, protocol.MaxPayloadBytes)
		if err != nil {
			problem(w, 400, "invalid diagnostic request")
			return
		}
		request, err := protocol.DecodeDiagnosticRequest(data)
		if err != nil {
			problem(w, 400, "invalid diagnostic profile or nodes")
			return
		}
		batch, err := s.Store.CreateDiagnosticBatch(r.Context(), u.Name, request)
		reply(w, batch, err)
	}))
	mux.HandleFunc("GET /v1/diagnostics/{id}", s.admin(false, func(w http.ResponseWriter, r *http.Request, u auth.User) {
		batch, err := s.Store.DiagnosticBatch(r.Context(), r.PathValue("id"))
		reply(w, batch, err)
	}))
	mux.HandleFunc("POST /v1/tasks/{id}/cancel", s.admin(true, func(w http.ResponseWriter, r *http.Request, u auth.User) {
		if !decode(w, r, &struct{}{}, 256) {
			return
		}
		reply(w, struct{}{}, s.Store.CancelTask(r.Context(), u.Name, r.PathValue("id")))
	}))
}
