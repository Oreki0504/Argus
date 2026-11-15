package api

import (
	"crypto/x509"
	"net/http"

	"github.com/Oreki0504/Argus-C2/internal/auth"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func (s *Server) capabilityRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/agent/capabilities", s.node(func(w http.ResponseWriter, r *http.Request, cert *x509.Certificate) {
		data, err := body(w, r, 4096)
		if err != nil {
			problem(w, 400, "invalid capabilities size")
			return
		}
		c, err := protocol.DecodeAgentCapabilities(data)
		if err != nil {
			problem(w, 400, "invalid capability report")
			return
		}
		reply(w, struct{}{}, s.Store.ReportCapabilities(r.Context(), cert, c))
	}))
	mux.HandleFunc("GET /v1/nodes/{id}/capabilities", s.admin(false, func(w http.ResponseWriter, r *http.Request, u auth.User) {
		c, err := s.Store.Capabilities(r.Context(), r.PathValue("id"))
		reply(w, c, err)
	}))
}
