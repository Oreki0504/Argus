package console

import (
	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"testing"
)

func TestTelemetryTrafficPreservesResetsBootsMissingIntervalsAndCapacity(t *testing.T) {
	sample := func(at int64, rx, tx uint64, boot, name string) *database.TelemetryObservation {
		return &database.TelemetryObservation{TelemetrySample: protocol.TelemetrySample{BootID: boot, ObservedAt: at, IntervalSeconds: 60, Metrics: protocol.SystemMeasurements{Disks: []protocol.DiskStats{}, Networks: []protocol.NetworkStats{{Interface: name, Available: true, RXBytes: rx, TXBytes: tx}}}}, ReceivedAt: 1000}
	}
	a, b := sample(100, 100, 200, "boot", "private0"), sample(160, 700, 1400, "boot", "private0")
	v := projectTelemetryTraffic(a, b)
	if v.Inbound == nil || *v.Inbound != 80 || v.Outbound == nil || *v.Outbound != 160 || v.InboundCapacity != nil || v.Coverage != nil || *v.AsOf != 160 {
		t.Fatal(v)
	}
	for _, pair := range [][2]*database.TelemetryObservation{
		{nil, b}, {b, a}, {a, sample(100, 700, 1400, "boot", "private0")},
		{a, sample(301, 700, 1400, "boot", "private0")},
		{a, sample(160, 700, 1400, "new-boot", "private0")},
		{a, sample(160, 700, 1400, "boot", "changed0")},
	} {
		if got := projectTelemetryTraffic(pair[0], pair[1]); got.Inbound != nil || got.Outbound != nil {
			t.Fatal("fabricated rate", got)
		}
	}
	b.ClockSkew = true
	if got := projectTelemetryTraffic(a, b); got.Inbound != nil {
		t.Fatal("clock-skew rate", got)
	}
	b.ClockSkew = false
	a.Metrics.Networks = append(a.Metrics.Networks, protocol.NetworkStats{Interface: "removed0", Available: true})
	if got := projectTelemetryTraffic(a, b); got.Inbound != nil {
		t.Fatal("changed network set", got)
	}
}
