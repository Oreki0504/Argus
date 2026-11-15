package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

func (r *Runner) capabilities() (protocol.AgentCapabilities, error) {
	p := r.Engine.Policy
	runtime := p.RuntimeTelemetry()
	p.TelemetryRuntime = &runtime
	p.Allowed = append([]protocol.TaskType{}, p.Allowed...)
	sort.Slice(p.Allowed, func(i, j int) bool { return p.Allowed[i] < p.Allowed[j] })
	raw, err := json.Marshal(p)
	if err != nil {
		return protocol.AgentCapabilities{}, err
	}
	digest := sha256.Sum256(raw)
	return protocol.AgentCapabilities{AgentVersion: protocol.BuildVersion(), ProtocolVersion: protocol.Version, PolicyVersion: 1, PolicyHash: hex.EncodeToString(digest[:]), SupportedCollectors: []protocol.TaskType{protocol.SystemInfo, protocol.SystemMetrics, protocol.ServiceStatus, protocol.NetworkListeners, protocol.ProcessList, protocol.SSHAudit}, AllowedCollectors: p.Allowed}, nil
}

func (r *Runner) reportCapabilities(ctx context.Context) error {
	if !r.capabilitiesSupported.Load() || time.Now().Before(r.nextCapabilities) {
		return nil
	}
	r.nextCapabilities = time.Now().Add(time.Minute)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	report, err := r.capabilities()
	if err != nil {
		return err
	}
	raw, err := r.request(ctx, "/v1/agent/capabilities", report)
	if err != nil {
		return err
	}
	if err = strictjson.Decode(raw, &struct{}{}, 256); err != nil {
		return errors.New("invalid capabilities acknowledgment")
	}
	r.nextCapabilities = time.Now().Add(time.Hour)
	return nil
}

func (r *Runner) capabilitiesLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.capabilitiesWake:
			if err := r.reportCapabilities(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("capability reporting deferred", "error", err)
			}
		}
	}
}
