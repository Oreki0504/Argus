package agent

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/enrollment"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
	"github.com/Oreki0504/Argus-C2/internal/transport"
)

type Runner struct {
	Server, CA, Dir       string
	Client                *http.Client
	Engine                *Engine
	cert                  *x509.Certificate
	nextRenewal           time.Time
	clientMu              sync.RWMutex
	renewMu               sync.Mutex
	telemetryMu           sync.Mutex
	telemetry             *TelemetryBuffer
	bootID                string
	startedAt             time.Time
	nextTelemetry         time.Time
	diagnosticMetadata    atomic.Bool
	capabilitiesSupported atomic.Bool
	capabilitiesWake      chan struct{}
	nextCapabilities      time.Time
	// Internal scheduling overrides allow concurrency tests without changing
	// the public 30-second minimum collection interval.
	testTelemetryInterval time.Duration
	testHeartbeatInterval time.Duration
}

func Open(server, ca, dir string, p policy.Policy) (*Runner, error) {
	if e := transport.ValidateURL(server); e != nil {
		return nil, e
	}
	if e := p.Validate(); e != nil {
		return nil, e
	}
	pair, e := transport.Pair(filepath.Join(dir, "agent.pem"), filepath.Join(dir, "agent-key.pem"))
	if e != nil {
		return nil, e
	}
	cert, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return nil, e
	}
	id, e := identity.FromCertificate(cert)
	if e != nil {
		return nil, e
	}
	key, e := loadKey(filepath.Join(dir, "agent-key.pem"))
	if e != nil {
		return nil, e
	}
	b, e := os.ReadFile(filepath.Join(dir, "agent.pem"))
	if e != nil {
		return nil, e
	}
	if _, e = verifyCertificate(string(b), key, ca, id); e != nil {
		return nil, e
	}
	state, e := OpenState(dir, id, false)
	if e != nil {
		return nil, e
	}
	client, e := transport.Client(ca, filepath.Join(dir, "agent.pem"), filepath.Join(dir, "agent-key.pem"))
	if e != nil {
		state.Close()
		return nil, e
	}
	bootID := identity.RandomID()
	return &Runner{Server: server, CA: ca, Dir: dir, Client: client, Engine: &Engine{State: state, Policy: p, BootID: bootID}, cert: cert, bootID: bootID, startedAt: time.Now()}, nil
}
func (r *Runner) Close() error {
	r.clientMu.RLock()
	if r.Client != nil {
		r.Client.CloseIdleConnections()
	}
	r.clientMu.RUnlock()
	var telemetryErr error
	r.telemetryMu.Lock()
	if r.telemetry != nil {
		telemetryErr = r.telemetry.Close()
	}
	r.telemetryMu.Unlock()
	return errors.Join(telemetryErr, r.Engine.State.Close())
}
func (r *Runner) request(ctx context.Context, path string, v any) ([]byte, error) {
	r.clientMu.RLock()
	client := r.Client
	r.clientMu.RUnlock()
	return transport.RequestWithHeaders(ctx, client, r.Server, "", "POST", path, v, func(header http.Header) {
		r.diagnosticMetadata.Store(len(header.Values(protocol.DiagnosticMetadataHeader)) == 1 && header.Get(protocol.DiagnosticMetadataHeader) == "1")
		r.capabilitiesSupported.Store(len(header.Values(protocol.CapabilitiesHeader)) == 1 && header.Get(protocol.CapabilitiesHeader) == "1")
	})
}
func (r *Runner) flush(ctx context.Context) error {
	// Bound one upload batch independently of the number of pending results.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	pending, e := r.Engine.State.Pending(ctx)
	if e != nil {
		return e
	}
	for _, result := range pending {
		if e = r.upload(ctx, result); e != nil {
			return e
		}
	}
	return nil
}
func (r *Runner) upload(ctx context.Context, result protocol.Result) error {
	b, e := r.request(ctx, "/v1/agent/results", result)
	if e != nil {
		var apiError *transport.APIError
		if errors.As(e, &apiError) && apiError.ResultRejection() {
			if e = r.Engine.State.Hold(ctx, result.TaskID, apiError.Code); e != nil {
				return e
			}
			slog.Warn("result requires operator attention", "task_id", result.TaskID, "code", apiError.Code)
			return nil
		}
		return e
	}
	// An arbitrary 2xx page is not an acknowledgment.
	if e = strictjson.Decode(b, &struct{}{}, 256); e != nil {
		return errors.New("invalid result acknowledgment")
	}
	return r.Engine.State.Acknowledge(ctx, result.TaskID)
}
func (r *Runner) Step(ctx context.Context) error {
	if e := r.Engine.State.Recover(ctx); e != nil {
		return e
	}
	if err := r.identityStep(ctx); err != nil {
		return err
	}
	flushErr := r.flush(ctx)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := r.heartbeat(ctx); err != nil {
		return err
	}
	if err := r.reportCapabilities(ctx); err != nil && ctx.Err() == nil {
		slog.Warn("capability reporting deferred", "error", err)
	}
	// Telemetry has independent error handling. Its storage or delivery failure
	// does not deny an otherwise valid diagnostic operation.
	if err := r.collectTelemetry(ctx); err != nil && ctx.Err() == nil {
		slog.Warn("telemetry collection deferred", "error", err)
	}
	if err := r.flushTelemetry(ctx); err != nil && ctx.Err() == nil {
		slog.Warn("telemetry delivery deferred", "error", err)
	}
	if flushErr != nil {
		return flushErr
	}
	return r.diagnostic(ctx, false)
}

func (r *Runner) identityStep(ctx context.Context) error {
	r.clientMu.RLock()
	cert := r.cert
	r.clientMu.RUnlock()
	now := time.Now()
	if cert == nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return errors.New("agent certificate is not currently valid; reenrollment required")
	}
	if time.Until(cert.NotAfter) < 7*24*time.Hour && !now.Before(r.nextRenewal) {
		// A renewal endpoint outage must not consume the whole communication
		// cycle or suppress uploads/heartbeats using a still-valid certificate.
		renewCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := r.Renew(renewCtx)
		cancel()
		r.clientMu.RLock()
		cert = r.cert
		r.clientMu.RUnlock()
		r.nextRenewal = time.Now().Add(min(5*time.Minute, max(time.Second, time.Until(cert.NotAfter)/2)))
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !time.Now().Before(cert.NotAfter) {
				return err
			}
			slog.Warn("certificate renewal failed; valid identity remains in use", "error", err, "certificate_expires_at", cert.NotAfter.Unix())
		}
	}
	return nil
}

func (r *Runner) heartbeat(ctx context.Context) error {
	host, e := os.Hostname()
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, e = r.request(ctx, "/v1/agent/heartbeat", protocol.Heartbeat{Hostname: host})
	if e == nil && r.capabilitiesWake != nil {
		select {
		case r.capabilitiesWake <- struct{}{}:
		default:
		}
	}
	return e
}

func (r *Runner) diagnostic(ctx context.Context, flush bool) error {
	if flush {
		if err := r.Engine.State.Recover(ctx); err != nil {
			return err
		}
		if err := r.flush(ctx); err != nil {
			return err
		}
	}
	b, e := r.request(ctx, "/v1/agent/poll", struct{}{})
	if e != nil || len(b) == 0 {
		return e
	}
	t, e := protocol.DecodeTask(b)
	if e != nil {
		return e
	}
	r.Engine.ReportMetadata = r.diagnosticMetadata.Load()
	result, e := r.Engine.Process(ctx, t, func(ctx context.Context, id string) error {
		b, e := r.request(ctx, "/v1/agent/tasks/"+id+"/running", struct{}{})
		if e != nil {
			return e
		}
		if strictjson.Decode(b, &struct{}{}, 256) != nil {
			return errors.New("invalid execution authorization response")
		}
		return nil
	})
	if errors.Is(e, ErrCapacity) || errors.Is(e, ErrResultHeld) || errors.Is(e, ErrResultDiscarded) {
		slog.Warn("task deferred locally", "task_id", t.ID, "reason", e)
		return nil
	}
	if e != nil {
		return e
	}
	return r.upload(ctx, result)
}
func (r *Runner) Renew(ctx context.Context) error {
	r.renewMu.Lock()
	defer r.renewMu.Unlock()
	key, e := loadKey(filepath.Join(r.Dir, "agent-key.pem"))
	if e != nil {
		return e
	}
	csr, e := enrollment.CSR(key)
	if e != nil {
		return e
	}
	b, e := r.request(ctx, "/v1/agent/renew", protocol.RenewalRequest{CSR: csr})
	if e != nil {
		return e
	}
	var response protocol.EnrollmentResponse
	if e = json.Unmarshal(b, &response); e != nil {
		return e
	}
	if response.NodeID != r.Engine.State.NodeID {
		return errors.New("renewal changed identity")
	}
	cert, e := verifyCertificate(response.Certificate, key, r.CA, response.NodeID)
	if e != nil {
		return e
	}
	if e = atomicWrite(filepath.Join(r.Dir, "agent.pem"), []byte(response.Certificate)); e != nil {
		return e
	}
	client, e := transport.Client(r.CA, filepath.Join(r.Dir, "agent.pem"), filepath.Join(r.Dir, "agent-key.pem"))
	if e != nil {
		return e
	}
	r.clientMu.Lock()
	previous := r.Client
	r.Client = client
	r.cert = cert
	r.clientMu.Unlock()
	previous.CloseIdleConnections()
	return nil
}
func (r *Runner) Run(ctx context.Context) error {
	if err := r.Engine.Policy.Validate(); err != nil {
		return err
	}
	var workers sync.WaitGroup
	r.capabilitiesWake = make(chan struct{}, 1)
	start := func(f func()) { workers.Add(1); go func() { defer workers.Done(); f() }() }
	heartbeatInterval := time.Duration(r.Engine.Policy.PollSeconds) * time.Second
	if r.testHeartbeatInterval > 0 {
		heartbeatInterval = r.testHeartbeatInterval
	}
	start(func() {
		r.repeat(ctx, "heartbeat", heartbeatInterval, func(ctx context.Context) error {
			if err := r.identityStep(ctx); err != nil {
				return err
			}
			return r.heartbeat(ctx)
		})
	})
	start(func() {
		r.repeat(ctx, "diagnostic", time.Duration(r.Engine.Policy.PollSeconds)*time.Second, func(ctx context.Context) error { return r.diagnostic(ctx, true) })
	})
	start(func() { r.capabilitiesLoop(ctx) })
	if r.Engine.Policy.RuntimeTelemetry().Enabled {
		start(func() { r.collectTelemetryLoop(ctx) })
		start(func() { r.repeat(ctx, "telemetry delivery", 5*time.Second, r.flushTelemetry) })
	}
	<-ctx.Done()
	workers.Wait()
	return nil
}

func (r *Runner) repeat(ctx context.Context, name string, interval time.Duration, operation func(context.Context) error) {
	delay := interval
	for ctx.Err() == nil {
		err := operation(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			slog.Warn(name+" failed; will retry", "error", err)
			delay = min(60*time.Second, max(interval, delay*2))
		} else {
			delay = interval
		}
		jitter := time.Duration(rand.IntN(1000)) * time.Millisecond
		if interval < time.Second {
			jitter = 0
		}
		timer := time.NewTimer(delay + jitter)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
