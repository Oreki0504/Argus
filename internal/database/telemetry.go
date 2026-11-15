package database

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

var ErrTelemetryConflict = fmt.Errorf("%w: telemetry sample ID reused", ErrConflict)
var ErrInvalidTelemetry = errors.New("invalid telemetry sample or observation time")

// Raw pages remain below the CLI transport bound even when every observation
// carries its maximum resource payload and calculated per-interface rates.
const MaxTelemetryPageBytes = 8 * 1024 * 1024

type TelemetryObservation struct {
	protocol.TelemetrySample
	NodeID        string                 `json:"node_id"`
	ReceivedAt    int64                  `json:"received_at"`
	SchemaVersion int                    `json:"schema_version"`
	ClockSkew     bool                   `json:"clock_skew"`
	NetworkRates  []TelemetryNetworkRate `json:"network_rates"`
}

type TelemetryNetworkRate struct {
	Interface        string  `json:"interface"`
	Available        bool    `json:"available"`
	RXBytesPerSecond float64 `json:"rx_bytes_per_second"`
	TXBytesPerSecond float64 `json:"tx_bytes_per_second"`
}

// SubmitTelemetry commits a complete batch or none of it. Authorization and
// insertion share a transaction, including requests on reused TLS connections.
func (s *Store) SubmitTelemetry(ctx context.Context, cert *x509.Certificate, batch protocol.TelemetryBatch) (protocol.TelemetryAck, error) {
	ack := protocol.TelemetryAck{SampleIDs: []string{}}
	if batch.SchemaVersion != protocol.TelemetrySchemaVersion || len(batch.Samples) < 1 || len(batch.Samples) > protocol.MaxTelemetryBatchSamples {
		return ack, ErrInvalidTelemetry
	}
	payloads := make([][]byte, len(batch.Samples))
	seen := map[string]bool{}
	for i, sample := range batch.Samples {
		var err error
		payloads[i], err = protocol.CanonicalTelemetrySample(sample)
		if err != nil || seen[sample.SampleID] {
			return ack, ErrInvalidTelemetry
		}
		seen[sample.SampleID] = true
	}
	now := s.now().Unix()
	var node, conflictID string
	err := s.Write(ctx, func(tx *sql.Tx) error {
		var err error
		if node, err = Authorize(ctx, tx, cert); err != nil {
			return err
		}
		inserted := []protocol.TelemetrySample{}
		for i, sample := range batch.Samples {
			var stored string
			err := tx.QueryRowContext(ctx, "SELECT payload_json FROM telemetry_samples WHERE node_id=? AND sample_id=?", node, sample.SampleID).Scan(&stored)
			if err == nil {
				if !bytes.Equal([]byte(stored), payloads[i]) {
					conflictID = sample.SampleID
					return ErrTelemetryConflict
				}
				continue
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if sample.ObservedAt > now+protocol.TelemetryFutureSkewSeconds || sample.ObservedAt < now-protocol.TelemetryRetentionSeconds {
				return ErrInvalidTelemetry
			}
			var cpu, total, available any
			if sample.Metrics.CPU.Available {
				cpu = sample.Metrics.CPU.BusyPercent
			}
			if sample.Metrics.Memory.Available {
				total = strconv.FormatUint(sample.Metrics.Memory.TotalBytes, 10)
				available = strconv.FormatUint(sample.Metrics.Memory.AvailableBytes, 10)
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO telemetry_samples(node_id,sample_id,boot_id,observed_at,received_at,agent_version,schema_version,interval_seconds,clock_skew,cpu_percent,memory_total_bytes,memory_available_bytes,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, node, sample.SampleID, sample.BootID, sample.ObservedAt, now, sample.AgentVersion, batch.SchemaVersion, sample.IntervalSeconds, sample.ObservedAt > now+60, cpu, total, available, string(payloads[i]))
			if err != nil {
				return err
			}
			inserted = append(inserted, sample)
		}
		return evaluateTelemetryAlerts(ctx, tx, node, inserted, now)
	})
	if errors.Is(err, ErrTelemetryConflict) {
		// A separate transaction preserves the conflict event after rolling back
		// the all-or-nothing sample batch. No observation payload enters logs.
		auditErr := s.Write(ctx, func(tx *sql.Tx) error {
			return auditSubject(ctx, tx, "node:"+node, "telemetry.conflict", node, "", conflictID, "rejected")
		})
		if auditErr != nil {
			slog.Error("telemetry conflict audit failed", "node_id", node, "sample_id", conflictID, "error", auditErr)
		}
		slog.Warn("telemetry sample ID conflict", "node_id", node, "sample_id", conflictID)
	}
	if err != nil {
		return ack, err
	}
	for _, sample := range batch.Samples {
		ack.SampleIDs = append(ack.SampleIDs, sample.SampleID)
	}
	return ack, nil
}

type TelemetryQuery struct {
	From, To int64
	Limit    int
	Cursor   string
}

type TelemetryPage struct {
	Items      []TelemetryObservation `json:"items"`
	NextCursor string                 `json:"next_cursor,omitempty"`
}

type telemetryCursor struct {
	NodeID     string `json:"node_id"`
	From       int64  `json:"from"`
	To         int64  `json:"to"`
	ObservedAt int64  `json:"observed_at"`
	SampleID   string `json:"sample_id"`
}

func (q TelemetryQuery) cursor(node string) (telemetryCursor, error) {
	var c telemetryCursor
	if !identity.Valid(node) || q.From <= 0 || q.To < q.From || q.To-q.From > protocol.TelemetryRetentionSeconds+protocol.TelemetryFutureSkewSeconds || q.Limit < 1 || q.Limit > 1000 {
		return c, errors.New("invalid telemetry query bounds")
	}
	if q.Cursor == "" {
		return c, nil
	}
	if len(q.Cursor) > 1024 {
		return c, errors.New("telemetry cursor too large")
	}
	b, err := base64.RawURLEncoding.DecodeString(q.Cursor)
	if err != nil || strictjson.Decode(b, &c, 768, "node_id", "from", "to", "observed_at", "sample_id") != nil || c.NodeID != node || c.From != q.From || c.To != q.To || c.ObservedAt < q.From || c.ObservedAt > q.To || !identity.Valid(c.SampleID) {
		return c, errors.New("telemetry cursor does not match query")
	}
	return c, nil
}

func (q TelemetryQuery) Validate(node string) error { _, err := q.cursor(node); return err }

const telemetryColumns = "node_id,received_at,schema_version,clock_skew,payload_json"

func scanTelemetry(row interface{ Scan(...any) error }) (TelemetryObservation, error) {
	var o TelemetryObservation
	var payload []byte
	if err := row.Scan(&o.NodeID, &o.ReceivedAt, &o.SchemaVersion, &o.ClockSkew, &payload); err != nil {
		return o, err
	}
	var err error
	o.TelemetrySample, err = protocol.DecodeTelemetrySample(payload)
	o.NetworkRates = []TelemetryNetworkRate{}
	return o, err
}

// QueryTelemetry uses a stable observation-time keyset. Delayed observations are
// ordered by measurement time; a prior sample outside the requested range is
// fetched only as a rate baseline, never exposed as an in-range observation.
func (s *Store) QueryTelemetry(ctx context.Context, node string, q TelemetryQuery) (TelemetryPage, error) {
	p := TelemetryPage{Items: []TelemetryObservation{}}
	c, err := q.cursor(node)
	if err != nil {
		return p, err
	}
	var exists int
	if err = s.DB.QueryRowContext(ctx, "SELECT 1 FROM nodes WHERE id=?", node).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	} else if err != nil {
		return p, err
	}
	conditions := "node_id=? AND observed_at>=? AND observed_at<=?"
	args := []any{node, q.From, q.To}
	if q.Cursor != "" {
		conditions += " AND (observed_at,sample_id)>(?,?)"
		args = append(args, c.ObservedAt, c.SampleID)
	}
	args = append(args, q.Limit+1)
	rows, err := s.DB.QueryContext(ctx, "SELECT "+telemetryColumns+" FROM telemetry_samples WHERE "+conditions+" ORDER BY observed_at,sample_id LIMIT ?", args...)
	if err != nil {
		return p, err
	}
	for rows.Next() {
		o, e := scanTelemetry(rows)
		if e != nil {
			rows.Close()
			return p, e
		}
		p.Items = append(p.Items, o)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(p.Items) == 0 {
		return p, err
	}
	hasMore := len(p.Items) > q.Limit
	if hasMore {
		p.Items = p.Items[:q.Limit]
	}
	first := p.Items[0]
	previous, err := scanTelemetry(s.DB.QueryRowContext(ctx, "SELECT "+telemetryColumns+" FROM telemetry_samples WHERE node_id=? AND (observed_at,sample_id)<(?,?) ORDER BY observed_at DESC,sample_id DESC LIMIT 1", node, first.ObservedAt, first.SampleID))
	var prior *TelemetryObservation
	if err == nil {
		prior = &previous
	} else if !errors.Is(err, sql.ErrNoRows) {
		return p, err
	}
	pageBytes := 2048 // Envelope, cursor and array punctuation allowance.
	for i := range p.Items {
		p.Items[i].NetworkRates = TelemetryNetworkRates(prior, &p.Items[i])
		encoded, err := json.Marshal(p.Items[i])
		if err != nil {
			return p, err
		}
		if i > 0 && pageBytes+len(encoded)+1 > MaxTelemetryPageBytes {
			p.Items = p.Items[:i]
			hasMore = true
			break
		}
		pageBytes += len(encoded) + 1
		prior = &p.Items[i]
	}
	if hasMore {
		last := p.Items[len(p.Items)-1]
		b, _ := json.Marshal(telemetryCursor{node, q.From, q.To, last.ObservedAt, last.SampleID})
		p.NextCursor = base64.RawURLEncoding.EncodeToString(b)
	}
	return p, nil
}

func (s *Store) LatestTelemetry(ctx context.Context, node string) (*TelemetryObservation, error) {
	o, err := scanTelemetry(s.DB.QueryRowContext(ctx, "SELECT "+telemetryColumns+" FROM telemetry_samples WHERE node_id=? ORDER BY observed_at DESC,sample_id DESC LIMIT 1", node))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	previous, err := scanTelemetry(s.DB.QueryRowContext(ctx, "SELECT "+telemetryColumns+" FROM telemetry_samples WHERE node_id=? AND (observed_at,sample_id)<(?,?) ORDER BY observed_at DESC,sample_id DESC LIMIT 1", node, o.ObservedAt, o.SampleID))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var prior *TelemetryObservation
	if err == nil {
		prior = &previous
	}
	o.NetworkRates = TelemetryNetworkRates(prior, &o)
	return &o, nil
}

func TelemetryNetworkRates(previous, current *TelemetryObservation) []TelemetryNetworkRate {
	out := []TelemetryNetworkRate{}
	if current == nil {
		return out
	}
	for _, n := range current.Metrics.Networks {
		rate := TelemetryNetworkRate{Interface: n.Interface}
		if previous != nil && previous.BootID == current.BootID && !previous.ClockSkew && !current.ClockSkew && n.Available {
			elapsed := current.ObservedAt - previous.ObservedAt
			if elapsed > 0 && elapsed <= int64(max(180, 3*max(previous.IntervalSeconds, current.IntervalSeconds))) {
				for _, prior := range previous.Metrics.Networks {
					if prior.Interface == n.Interface && prior.Available && n.RXBytes >= prior.RXBytes && n.TXBytes >= prior.TXBytes {
						rate.Available = true
						rate.RXBytesPerSecond = float64(n.RXBytes-prior.RXBytes) / float64(elapsed)
						rate.TXBytesPerSecond = float64(n.TXBytes-prior.TXBytes) / float64(elapsed)
						break
					}
				}
			}
		}
		out = append(out, rate)
	}
	return out
}

type TelemetryStatus struct {
	Telemetry  string `json:"telemetry"`
	Health     string `json:"health"`
	ObservedAt int64  `json:"observed_at"`
}

// Health is based on complete, recent measurement evidence. Connectivity and
// authorization remain independent and cannot turn absent metrics green.
func ProjectTelemetryStatus(latest *TelemetryObservation, now int64) TelemetryStatus {
	s := TelemetryStatus{Telemetry: "MISSING", Health: "UNKNOWN"}
	if latest == nil {
		return s
	}
	s.ObservedAt = latest.ObservedAt
	s.Telemetry = "STALE"
	if latest.ClockSkew || latest.ObservedAt > now || now-latest.ObservedAt > int64(max(180, 3*latest.IntervalSeconds)) {
		return s
	}
	s.Telemetry = "FRESH"
	m := latest.Metrics
	complete := m.CPU.Available && m.Memory.Available && latest.System.Available && len(m.Disks) > 0 && len(m.Networks) > 0 && len(latest.Errors) == 0
	severity := 0
	check := func(value, warning, critical float64) {
		if value >= critical {
			severity = max(severity, 2)
		} else if value >= warning {
			severity = max(severity, 1)
		}
	}
	if m.CPU.Available {
		check(m.CPU.BusyPercent, 80, 90)
	}
	if m.Memory.Available {
		check(100*(1-float64(m.Memory.AvailableBytes)/float64(m.Memory.TotalBytes)), 85, 95)
	}
	for _, d := range m.Disks {
		complete = complete && d.Available && d.TotalBytes > 0
		if d.Available && d.TotalBytes > 0 {
			check(100*(1-float64(d.AvailableBytes)/float64(d.TotalBytes)), 85, 95)
		}
	}
	for _, n := range m.Networks {
		complete = complete && n.Available
	}
	if latest.Agent.BufferedSamples >= 1800 {
		severity = max(severity, 1)
	}
	if severity == 2 {
		s.Health = "CRITICAL"
	} else if severity == 1 {
		s.Health = "WARNING"
	} else if complete {
		s.Health = "HEALTHY"
	}
	return s
}
