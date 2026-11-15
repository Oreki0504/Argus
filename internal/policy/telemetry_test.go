package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestTelemetrySettingsRemainLocalAndIndependent(t *testing.T) {
	p := Default()
	p.Allowed = []protocol.TaskType{}
	if settings := p.RuntimeTelemetry(); !settings.Enabled || settings.IntervalSeconds != 60 || settings.BufferMaxBytes != 32*1024*1024 {
		t.Fatal(settings)
	}
	p.TelemetryRuntime = &TelemetryRuntime{Enabled: false, IntervalSeconds: 30, BufferMaxBytes: 1024 * 1024}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(b)
	if err != nil || decoded.RuntimeTelemetry().Enabled {
		t.Fatal(decoded, err)
	}
	for _, changed := range []string{
		strings.Replace(string(b), `"interval_seconds":30`, `"interval_seconds":29`, 1),
		strings.Replace(string(b), `"interval_seconds":30`, `"interval_seconds":301`, 1),
		strings.Replace(string(b), `"enabled":false,`, "", 1),
		strings.Replace(string(b), `"telemetry_runtime":{`, `"telemetry_runtime":{"remote_override":true,`, 1),
	} {
		if _, err := Decode([]byte(changed)); err == nil {
			t.Fatal("invalid settings accepted", changed)
		}
	}
}
