package policy

import "errors"

// TelemetryRuntime is independent of the diagnostic collector allowlist.
// Only the local policy file may enable collection or change its bounds.
type TelemetryRuntime struct {
	Enabled         bool  `json:"enabled"`
	IntervalSeconds int   `json:"interval_seconds"`
	BufferMaxBytes  int64 `json:"buffer_max_bytes"`
}

func (p Policy) RuntimeTelemetry() TelemetryRuntime {
	if p.TelemetryRuntime != nil {
		return *p.TelemetryRuntime
	}
	return TelemetryRuntime{Enabled: true, IntervalSeconds: 60, BufferMaxBytes: 32 * 1024 * 1024}
}

func (t TelemetryRuntime) Validate() error {
	if t.IntervalSeconds < 30 || t.IntervalSeconds > 300 || t.BufferMaxBytes < 1024*1024 || t.BufferMaxBytes > 256*1024*1024 {
		return errors.New("telemetry interval must be 30-300 seconds and buffer size 1-256 MiB")
	}
	return nil
}
