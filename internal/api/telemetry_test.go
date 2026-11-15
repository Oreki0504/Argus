package api

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/auth"
	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestTelemetryHTTPIdentityStrictnessAndQueryAuthorization(t *testing.T) {
	s, err := database.Open(filepath.Join(t.TempDir(), "state"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	c := &x509.Certificate{Raw: []byte("telemetry-http"), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity.URI("node")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	if _, err = s.DB.Exec("INSERT INTO nodes(id,hostname,certificate_fingerprint,status,created_at,certificate_expires_at,certificate) VALUES('node','host',?,'active',1,9999999999,'cert')", identity.Fingerprint(c)); err != nil {
		t.Fatal(err)
	}
	u, token, err := auth.NewUser("reader", "ReadOnly")
	if err != nil {
		t.Fatal(err)
	}
	h := (&Server{Store: s, Admins: auth.Config{Users: []auth.User{u}}}).Handler()
	sample := protocol.TelemetrySample{SampleID: "sample", BootID: "boot", ObservedAt: now.Unix(), AgentVersion: "test", IntervalSeconds: 60, Metrics: protocol.SystemMeasurements{Disks: []protocol.DiskStats{}, Networks: []protocol.NetworkStats{}}, System: protocol.SystemInformation{OS: "linux", Architecture: "amd64"}, Errors: []protocol.TelemetryCollectionError{}}
	raw, _ := json.Marshal(protocol.TelemetryBatch{SchemaVersion: 1, Samples: []protocol.TelemetrySample{sample}})
	request := func(method, path string, data []byte, mode string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://server"+path, bytes.NewReader(data))
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}, VerifiedChains: [][]*x509.Certificate{{c}}}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(protocol.VersionHeader, strconv.Itoa(protocol.Version))
		r.Header.Set(protocol.AgentVersionHeader, "test")
		switch mode {
		case "unverified":
			r.TLS.VerifiedChains = nil
		case "wrong-fingerprint":
			copy := *c
			copy.Raw = []byte("wrong")
			r.TLS.PeerCertificates = []*x509.Certificate{&copy}
		case "protocol":
			r.Header.Set(protocol.VersionHeader, "999")
		case "reader":
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for mode, status := range map[string]int{"valid": 200, "unverified": 401, "wrong-fingerprint": 401, "protocol": 426} {
		if w := request(http.MethodPost, "/v1/agent/telemetry", raw, mode); w.Code != status {
			t.Fatal(mode, w.Code, w.Body.String())
		}
	}
	for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"sample_id":"sample"`), []byte(`"node_id":"other","sample_id":"sample"`), 1), bytes.Repeat([]byte(" "), protocol.MaxTelemetryBatchBytes+1)} {
		if w := request(http.MethodPost, "/v1/agent/telemetry", bad, "valid"); w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	sample.Agent.DroppedSamples = 1
	changed, _ := json.Marshal(protocol.TelemetryBatch{SchemaVersion: 1, Samples: []protocol.TelemetrySample{sample}})
	if w := request(http.MethodPost, "/v1/agent/telemetry", changed, "valid"); w.Code != 409 || !strings.Contains(w.Body.String(), "telemetry_conflict") {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request(http.MethodGet, "/v1/nodes/node/telemetry", nil, "valid"); w.Code != 401 {
		t.Fatal("node cert accessed admin history", w.Code)
	}
	if w := request(http.MethodGet, "/v1/nodes/node/telemetry", nil, "reader"); w.Code != 200 || !strings.Contains(w.Body.String(), `"sample_id":"sample"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, query := range []string{"?limit=1001", "?limit=1&limit=2", "?unexpected=1", "?from=-1", "?cursor=bad"} {
		if w := request(http.MethodGet, "/v1/nodes/node/telemetry"+query, nil, "reader"); w.Code != 400 {
			t.Fatal(query, w.Code, w.Body.String())
		}
	}
	if err = s.Disable(t.Context(), "admin", "node"); err != nil {
		t.Fatal(err)
	}
	if w := request(http.MethodPost, "/v1/agent/telemetry", raw, "valid"); w.Code != 401 {
		t.Fatal("disabled existing connection accepted", w.Code)
	}
}
