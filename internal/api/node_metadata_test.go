package api

import (
	"bytes"
	"crypto/tls"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/auth"
	"github.com/Oreki0504/Argus-C2/internal/database"
)

func TestNodeMetadataHTTPRolesAndValidation(t *testing.T) {
	s, err := database.Open(filepath.Join(t.TempDir(), "state"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.DB.Exec("INSERT INTO nodes(id,hostname,certificate_fingerprint,status,created_at,certificate_expires_at,certificate) VALUES('node','host','fp','active',1,9999999999,'cert')"); err != nil {
		t.Fatal(err)
	}
	reader, readToken, err := auth.NewUser("reader", "ReadOnly")
	if err != nil {
		t.Fatal(err)
	}
	admin, adminToken, err := auth.NewUser("admin", "Admin")
	if err != nil {
		t.Fatal(err)
	}
	h := (&Server{Store: s, Admins: auth.Config{Users: []auth.User{reader, admin}}}).Handler()
	request := func(method, path, token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://server"+path, bytes.NewBufferString(body))
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, route := range []struct{ method, path, body string }{{"PUT", "/v1/nodes/node/tags", `{"tags":["prod"]}`}, {"POST", "/v1/nodes/node/revoke", `{}`}} {
		if w := request(route.method, route.path, readToken, route.body); w.Code != 403 {
			t.Fatal("reader mutated node", w.Code, w.Body.String())
		}
		if w := request(route.method, route.path, adminToken, route.body); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	for _, body := range []string{`{"tags":null}`, `{"tags":["a","a"]}`, `{"tags":["a"],"extra":1}`} {
		if w := request("PUT", "/v1/nodes/node/tags", adminToken, body); w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if w := request("POST", "/v1/nodes/missing/revoke", adminToken, `{}`); w.Code != 404 {
		t.Fatal(w.Code, w.Body.String())
	}
}
