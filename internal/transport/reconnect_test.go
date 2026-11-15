package transport

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func trustedTestClient(t *testing.T, handler http.Handler) (*http.Client, string) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(protocol.VersionHeader, strconv.Itoa(protocol.Version))
		w.Header().Set("Content-Type", "application/json")
		handler.ServeHTTP(w, r)
	}))
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := Client(ca, "", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.CloseIdleConnections(); server.Close() })
	return client, server.URL
}

func TestReplaySafeResultReconnectsWithoutReplayingTaskCreation(t *testing.T) {
	for _, path := range []string{"/v1/agent/results", "/v1/tasks"} {
		t.Run(path, func(t *testing.T) {
			var attempts atomic.Int32
			client, origin := trustedTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					return
				}
				if r.URL.Path == "/v1/health" {
					io.WriteString(w, "{}")
					return
				}
				if string(body) != `{"sample":"immutable"}` {
					t.Errorf("request payload changed: %s", body)
				}
				if _, present := r.Header["Idempotency-Key"]; present {
					t.Error("internal replay marker sent over wire")
				}
				if attempts.Add(1) == 1 {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					conn.Close()
					return
				}
				io.WriteString(w, "{}")
			}))
			if _, err := Request(t.Context(), client, origin, "", "GET", "/v1/health", nil); err != nil {
				t.Fatal(err)
			}
			_, err := Request(t.Context(), client, origin, "", "POST", path, map[string]string{"sample": "immutable"})
			if path == "/v1/agent/results" {
				if err != nil || attempts.Load() != 2 {
					t.Fatal("idempotent result did not reconnect", attempts.Load(), err)
				}
			} else if err == nil || attempts.Load() != 1 {
				t.Fatal("task creation was replayed", attempts.Load(), err)
			}
		})
	}
}

func TestBlockedUploadsLeaveConnectionForHeartbeat(t *testing.T) {
	started := make(chan struct{}, 3)
	client, origin := trustedTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/v1/agent/heartbeat" {
			io.WriteString(w, "{}")
			return
		}
		started <- struct{}{}
		<-r.Context().Done()
	}))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	completed := make(chan struct{}, 3)
	for _, path := range []string{"/v1/agent/results", "/v1/agent/telemetry", "/v1/agent/capabilities"} {
		go func(path string) { Request(ctx, client, origin, "", "POST", path, struct{}{}); completed <- struct{}{} }(path)
	}
	for range 3 {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("upload connection did not start")
		}
	}
	heartbeatCtx, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	if _, err := Request(heartbeatCtx, client, origin, "", "POST", "/v1/agent/heartbeat", struct{}{}); err != nil {
		t.Fatal("blocked uploads starved heartbeat", err)
	}
	cancel()
	for range 3 {
		select {
		case <-completed:
		case <-time.After(2 * time.Second):
			t.Fatal("upload did not stop")
		}
	}
}
