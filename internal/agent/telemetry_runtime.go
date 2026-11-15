package agent

import (
	"context"
	"errors"
	"log/slog"
	"time"

	collector "github.com/Oreki0504/Argus-C2/internal/collectors/system"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
	"github.com/Oreki0504/Argus-C2/internal/transport"
)

func (r *Runner) telemetryBuffer() (*TelemetryBuffer, error) {
	r.telemetryMu.Lock()
	defer r.telemetryMu.Unlock()
	if r.telemetry != nil {
		return r.telemetry, nil
	}
	b, err := OpenTelemetryBuffer(r.Dir, r.Engine.State.NodeID, r.Engine.Policy.RuntimeTelemetry().BufferMaxBytes, true)
	if err != nil {
		return nil, err
	}
	r.telemetry = b
	return b, nil
}

func (r *Runner) telemetryInterval() time.Duration {
	if r.testTelemetryInterval > 0 {
		return r.testTelemetryInterval
	}
	return time.Duration(r.Engine.Policy.RuntimeTelemetry().IntervalSeconds) * time.Second
}

func (r *Runner) collectTelemetryLoop(ctx context.Context) {
	for ctx.Err() == nil {
		if err := r.collectTelemetry(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("telemetry collection deferred", "error", err)
		}
		// A delayed collector schedules one useful current observation. It never
		// synthesizes samples for missed intervals after sleep or an outage.
		delay := time.Until(r.nextTelemetry)
		if delay <= 0 {
			delay = r.telemetryInterval()
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (r *Runner) collectTelemetry(ctx context.Context) error {
	settings := r.Engine.Policy.RuntimeTelemetry()
	if !settings.Enabled || time.Now().Before(r.nextTelemetry) {
		return nil
	}
	r.nextTelemetry = time.Now().Add(r.telemetryInterval())
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	buffer, err := r.telemetryBuffer()
	if err != nil {
		return err
	}
	status, err := buffer.Status(ctx)
	if err != nil {
		return err
	}
	if r.bootID == "" {
		r.bootID = identity.RandomID()
	}
	if r.startedAt.IsZero() {
		r.startedAt = time.Now()
	}
	metrics, metricsErr := collector.Measurements(ctx, r.Engine.Policy.Telemetry)
	info, infoErr := collector.Information(ctx)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	collected := time.Now()
	sample := protocol.TelemetrySample{
		SampleID: identity.RandomID(), BootID: r.bootID, ObservedAt: collected.Unix(),
		AgentVersion: protocol.BuildVersion(), IntervalSeconds: settings.IntervalSeconds,
		Metrics: metrics, System: info,
		Agent:  protocol.TelemetryAgentHealth{UptimeSeconds: int64(time.Since(r.startedAt) / time.Second), BufferedSamples: status.Samples, DroppedSamples: status.DroppedExpired + status.DroppedCapacity},
		Errors: []protocol.TelemetryCollectionError{},
	}
	addError := func(resource, code string) {
		sample.Errors = append(sample.Errors, protocol.TelemetryCollectionError{ResourceID: resource, Code: code})
	}
	if metricsErr != nil {
		addError("metrics", "collection_failed")
	}
	if infoErr != nil {
		addError("system", "collection_failed")
	} else if !info.Available {
		addError("system", "unavailable")
	}
	if !metrics.CPU.Available {
		addError("cpu", "unavailable")
	}
	if !metrics.Memory.Available {
		addError("memory", "unavailable")
	}
	for _, disk := range metrics.Disks {
		if !disk.Available {
			addError(disk.Path, "unavailable")
		}
	}
	for _, network := range metrics.Networks {
		if !network.Available {
			addError("network:"+network.Interface, "unavailable")
		}
	}
	if len(metrics.Networks) == 0 {
		addError("network", "unavailable")
	}
	if err = buffer.Add(ctx, sample, collected); err != nil {
		return err
	}
	after, err := buffer.Status(ctx)
	if err == nil && (after.DroppedExpired != status.DroppedExpired || after.DroppedCapacity != status.DroppedCapacity) {
		slog.Warn("telemetry buffer evicted old samples", "dropped_expired", after.DroppedExpired, "dropped_capacity", after.DroppedCapacity, "buffered_samples", after.Samples)
	}
	return err
}

func telemetryRejected(err error) (*transport.APIError, bool) {
	var failure *transport.APIError
	if errors.As(err, &failure) && (failure.Status == 400 && failure.Code == "telemetry_invalid" || failure.Status == 409 && failure.Code == "telemetry_conflict") {
		return failure, true
	}
	return nil, false
}

func (r *Runner) sendTelemetry(ctx context.Context, buffer *TelemetryBuffer, samples []protocol.TelemetrySample) error {
	raw, err := r.request(ctx, "/v1/agent/telemetry", protocol.TelemetryBatch{SchemaVersion: protocol.TelemetrySchemaVersion, Samples: samples})
	if err != nil {
		return err
	}
	var ack protocol.TelemetryAck
	if err = strictjson.Decode(raw, &ack, 16*1024, "sample_ids"); err != nil {
		return errors.New("invalid telemetry acknowledgment")
	}
	return buffer.Acknowledge(ctx, samples, ack)
}

func (r *Runner) flushTelemetry(ctx context.Context) error {
	if !r.Engine.Policy.RuntimeTelemetry().Enabled {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	buffer, err := r.telemetryBuffer()
	if err != nil {
		return err
	}
	samples, err := buffer.Pending(ctx, time.Now())
	if err != nil || len(samples) == 0 {
		return err
	}
	err = r.sendTelemetry(ctx, buffer, samples)
	if _, rejected := telemetryRejected(err); !rejected {
		return err
	}
	// A batch-level business rejection may concern only one observation. Keep
	// transient failures pending, isolate definite rejections, and allow valid
	// observations to progress. Held data remains bounded and visible locally.
	for _, sample := range samples {
		err = r.sendTelemetry(ctx, buffer, []protocol.TelemetrySample{sample})
		if err == nil {
			continue
		}
		failure, rejected := telemetryRejected(err)
		if !rejected {
			return err
		}
		if err = buffer.Hold(ctx, sample.SampleID, failure.Code); err != nil {
			return err
		}
		slog.Warn("telemetry sample retained after server rejection", "sample_id", sample.SampleID, "code", failure.Code)
	}
	return nil
}
