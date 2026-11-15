package api

import (
	"net/http"

	"github.com/Oreki0504/Argus-C2/internal/auth"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func (s *Server) nodeMetadataRoutes(mux *http.ServeMux) {
	mux.HandleFunc("PUT /v1/nodes/{id}/tags", s.admin(true, func(w http.ResponseWriter, r *http.Request, u auth.User) {
		var v struct {
			Tags []string `json:"tags"`
		}
		if !decode(w, r, &v, 2048, "tags") {
			return
		}
		if !protocol.ValidNodeTags(v.Tags) {
			problem(w, 400, "invalid node tags")
			return
		}
		reply(w, struct{}{}, s.Store.SetNodeTags(r.Context(), u.Name, r.PathValue("id"), v.Tags))
	}))
	mux.HandleFunc("POST /v1/nodes/{id}/revoke", s.admin(true, func(w http.ResponseWriter, r *http.Request, u auth.User) {
		if !decode(w, r, &struct{}{}, 256) {
			return
		}
		reply(w, struct{}{}, s.Store.RevokeNode(r.Context(), u.Name, r.PathValue("id")))
	}))
}
