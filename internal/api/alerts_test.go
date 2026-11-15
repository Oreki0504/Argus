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
)

func TestAlertHTTPReadWriteAuthorizationAndStrictQuery(t *testing.T) {
	s, err := database.Open(filepath.Join(t.TempDir(), "state"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	reader, readToken, err := auth.NewUser("reader", "ReadOnly")
	if err != nil {
		t.Fatal(err)
	}
	admin, adminToken, err := auth.NewUser("admin", "Admin")
	if err != nil {
		t.Fatal(err)
	}
	h := (&Server{Store: s, Admins: auth.Config{Users: []auth.User{reader, admin}}}).Handler()
	req := func(method, path, token string, body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://server"+path, bytes.NewReader(body))
		r.TLS = &tls.ConnectionState{}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/v1/alerts", "/v1/alert-events", "/v1/alert-rules"} {
		if w := req("GET", path, "", nil); w.Code != 401 {
			t.Fatal(path, w.Code)
		}
		if w := req("GET", path, readToken, nil); w.Code != 200 {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	rule := database.AlertRule{ID: "custom", Metric: "cpu_percent", Severity: "WARNING", Threshold: 75, ForSeconds: 120, RecoverySeconds: 120, Enabled: true}
	raw, _ := json.Marshal(rule)
	if w := req("PUT", "/v1/alert-rules/custom", readToken, raw); w.Code != 403 {
		t.Fatal("reader modified rules", w.Code, w.Body.String())
	}
	if w := req("PUT", "/v1/alert-rules/custom", adminToken, raw); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := req("PUT", "/v1/alert-rules/other", adminToken, raw); w.Code != 400 {
		t.Fatal("ID mismatch accepted", w.Code)
	}
	bad := bytes.Replace(raw, []byte(`"threshold":75`), []byte(`"threshold":75,"threshold":80`), 1)
	if w := req("PUT", "/v1/alert-rules/custom", adminToken, bad); w.Code != 400 {
		t.Fatal("ambiguous rule accepted", w.Code)
	}
	for _, path := range []string{"/v1/alerts?limit=201", "/v1/alerts?limit=1&limit=2", "/v1/alerts?status=UNKNOWN", "/v1/alerts?cursor=bad", "/v1/alert-events?after=-1", "/v1/alert-events?limit=201", "/v1/alert-events?unknown=1", "/v1/alert-rules?limit=20"} {
		if w := req("GET", path, readToken, nil); w.Code != 400 {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
}
