package console

import "github.com/Oreki0504/Argus-C2/internal/database"

// Public rates aggregate only a complete set of valid per-interface rates.
// Capacity and window totals remain absent unless independently measured.
func projectTelemetryTraffic(previous, current *database.TelemetryObservation) publicTraffic {
	var out publicTraffic
	if previous == nil || current == nil || previous.ClockSkew || current.ClockSkew || len(previous.Metrics.Networks) != len(current.Metrics.Networks) {
		return out
	}
	rates := database.TelemetryNetworkRates(previous, current)
	if len(rates) == 0 || len(rates) != len(current.Metrics.Networks) {
		return out
	}
	var rx, tx float64
	for _, rate := range rates {
		if !rate.Available {
			return out
		}
		rx += rate.RXBytesPerSecond
		tx += rate.TXBytesPerSecond
	}
	out.AsOf = ptr(current.ObservedAt)
	out.Inbound = ptr(rx * 8)
	out.Outbound = ptr(tx * 8)
	return out
}
