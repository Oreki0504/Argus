package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/auth"
	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestDiagnosticProfileHTTPAuthorizationAndAtomicity(t *testing.T) {
	s, err := database.Open(filepath.Join(t.TempDir(), "state"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.DB.Exec("INSERT INTO nodes(id,hostname,certificate_fingerprint,status,created_at,certificate_expires_at,certificate) VALUES('node','host','fp','active',1,9999999999,'cert')"); err != nil {
		t.Fatal(err)
	}
	admin, token, _ := auth.NewUser("admin", "Admin")
	reader, readToken, _ := auth.NewUser("reader", "ReadOnly")
	h := (&Server{Store: s, Admins: auth.Config{Users: []auth.User{admin, reader}}}).Handler()
	call := func(method, path, bearer string, body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://server"+path, bytes.NewReader(body))
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	request := protocol.DiagnosticRequest{NodeIDs: []string{"node"}, ProfileID: "system", TTLSeconds: 300, ExecutionTimeoutMS: 10000}
	data, _ := json.Marshal(request)
	for bearer, code := range map[string]int{"": 401, readToken: 403} {
		if w := call("POST", "/v1/diagnostics", bearer, data); w.Code != code {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	for _, bad := range [][]byte{
		bytes.Replace(data, []byte(`"system"`), []byte(`"arbitrary"`), 1),
		bytes.Replace(data, []byte(`["node"]`), []byte(`["node","node"]`), 1),
		bytes.Replace(data, []byte(`"resource_id":""`), []byte(`"resource_id":"","command":"id"`), 1),
	} {
		if w := call("POST", "/v1/diagnostics", token, bad); w.Code != 400 {
			t.Fatal("invalid profile accepted", w.Code, w.Body.String())
		}
	}
	w := call("POST", "/v1/diagnostics", token, data)
	var batch database.DiagnosticBatch
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &batch) != nil || len(batch.Tasks) != 2 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("GET", "/v1/diagnostics/"+batch.ID, readToken, nil); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	path := "/v1/tasks/" + batch.Tasks[0].ID + "/cancel"
	if w := call("POST", path, readToken, []byte(`{}`)); w.Code != 403 {
		t.Fatal("read-only cancellation", w.Code)
	}
	for range 2 {
		if w := call("POST", path, token, []byte(`{}`)); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	request.NodeIDs = append(request.NodeIDs, "missing")
	data, _ = json.Marshal(request)
	if w := call("POST", "/v1/diagnostics", token, data); w.Code != 404 {
		t.Fatal(w.Code, w.Body.String())
	}
	var count int
	if err := s.DB.QueryRow("SELECT count(*) FROM tasks").Scan(&count); err != nil || count != 2 {
		t.Fatal("partial submission", count, err)
	}
}
