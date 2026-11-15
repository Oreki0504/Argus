package agent

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/localdb"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

const TelemetryBufferSchemaVersion = 1
const telemetryApplicationID = 0x41524754 // ARGT, separate from replay state.
const TelemetryBufferLimit = 2000
const TelemetryBufferMaxAge = 24 * time.Hour

// TelemetryBuffer has its own database so pressure or corruption here does not
// change the execution grants, deduplication, or durable diagnostic results.
// The caller holds the existing probe process lock while using this database.
type TelemetryBuffer struct {
	db       *sql.DB
	maxBytes int64
}

type TelemetryBufferStatus struct {
	Samples         int    `json:"samples"`
	HeldSamples     int    `json:"held_samples"`
	PayloadBytes    int64  `json:"payload_bytes"`
	MaxBytes        int64  `json:"max_bytes"`
	DroppedExpired  uint64 `json:"dropped_expired"`
	DroppedCapacity uint64 `json:"dropped_capacity"`
}

// OpenTelemetryBuffer never modifies a database belonging to another identity
// or schema. Creation is safe only after the durable probe identity is opened.
func OpenTelemetryBuffer(dir, nodeID string, maxBytes int64, create bool) (*TelemetryBuffer, error) {
	if !identity.Valid(nodeID) || maxBytes < 1024*1024 || maxBytes > 256*1024*1024 {
		return nil, errors.New("invalid telemetry buffer configuration")
	}
	db, err := localdb.Open(dir, "telemetry.db", create)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*TelemetryBuffer, error) { db.Close(); return nil, err }
	var version, component, tables int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fail(err)
	}
	if err = db.QueryRow("PRAGMA application_id").Scan(&component); err != nil {
		return fail(err)
	}
	if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tables); err != nil {
		return fail(err)
	}
	if version == 0 && component == 0 && tables == 0 && create {
		tx, err := db.Begin()
		if err != nil {
			return fail(err)
		}
		_, err = tx.Exec(`CREATE TABLE telemetry_identity(node_id TEXT PRIMARY KEY, dropped_expired INTEGER NOT NULL DEFAULT 0,dropped_capacity INTEGER NOT NULL DEFAULT 0);
CREATE TABLE telemetry_buffer(sample_id TEXT PRIMARY KEY,observed_at INTEGER NOT NULL,payload TEXT NOT NULL CHECK(json_valid(payload)),held INTEGER NOT NULL DEFAULT 0 CHECK(held IN (0,1)),hold_reason TEXT NOT NULL DEFAULT '');
CREATE INDEX telemetry_buffer_observed ON telemetry_buffer(observed_at,sample_id);
PRAGMA user_version=1; PRAGMA application_id=1095911252;
INSERT INTO telemetry_identity(node_id) VALUES(?)`, nodeID)
		if err != nil {
			tx.Rollback()
			return fail(err)
		}
		if err = tx.Commit(); err != nil {
			return fail(err)
		}
	} else if version != TelemetryBufferSchemaVersion || component != telemetryApplicationID {
		return fail(errors.New("incompatible telemetry buffer; preserve existing observations"))
	}
	var actual string
	if err = db.QueryRow("SELECT node_id FROM telemetry_identity").Scan(&actual); err != nil {
		return fail(err)
	}
	if actual != nodeID {
		return fail(errors.New("telemetry buffer belongs to another node"))
	}
	return &TelemetryBuffer{db: db, maxBytes: maxBytes}, nil
}

func (b *TelemetryBuffer) Close() error { return b.db.Close() }

func (b *TelemetryBuffer) trim(ctx context.Context, tx *sql.Tx, now time.Time) error {
	res, err := tx.ExecContext(ctx, "DELETE FROM telemetry_buffer WHERE observed_at<?", now.Add(-TelemetryBufferMaxAge).Unix())
	if err != nil {
		return err
	}
	expired, err := res.RowsAffected()
	if err != nil {
		return err
	}
	var count, bytes int64
	if err = tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(length(CAST(payload AS BLOB))),0) FROM telemetry_buffer").Scan(&count, &bytes); err != nil {
		return err
	}
	var dropped int64
	for count > TelemetryBufferLimit || bytes > b.maxBytes {
		var id string
		var size int64
		if err = tx.QueryRowContext(ctx, "SELECT sample_id,length(CAST(payload AS BLOB)) FROM telemetry_buffer ORDER BY observed_at,sample_id LIMIT 1").Scan(&id, &size); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM telemetry_buffer WHERE sample_id=?", id); err != nil {
			return err
		}
		count--
		bytes -= size
		dropped++
	}
	_, err = tx.ExecContext(ctx, "UPDATE telemetry_identity SET dropped_expired=dropped_expired+?,dropped_capacity=dropped_capacity+?", expired, dropped)
	return err
}

func (b *TelemetryBuffer) Add(ctx context.Context, sample protocol.TelemetrySample, now time.Time) error {
	if err := sample.Validate(); err != nil {
		return err
	}
	payload, err := protocol.CanonicalTelemetrySample(sample)
	if err != nil {
		return err
	}
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var previous string
	err = tx.QueryRowContext(ctx, "SELECT payload FROM telemetry_buffer WHERE sample_id=?", sample.SampleID).Scan(&previous)
	if err == nil && previous != string(payload) {
		return errors.New("telemetry sample ID reused with different payload")
	}
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.ExecContext(ctx, "INSERT INTO telemetry_buffer(sample_id,observed_at,payload) VALUES(?,?,?)", sample.SampleID, sample.ObservedAt, string(payload))
	}
	if err != nil {
		return err
	}
	if err = b.trim(ctx, tx, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (b *TelemetryBuffer) Pending(ctx context.Context, now time.Time) ([]protocol.TelemetrySample, error) {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = b.trim(ctx, tx, now); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	rows, err := b.db.QueryContext(ctx, "SELECT payload FROM telemetry_buffer WHERE held=0 ORDER BY observed_at,sample_id LIMIT ?", protocol.MaxTelemetryBatchSamples)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []protocol.TelemetrySample{}
	// Account for the batch envelope before adding bounded serialized samples.
	size := 64
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if size+len(raw)+1 > protocol.MaxTelemetryBatchBytes {
			break
		}
		sample, err := protocol.DecodeTelemetrySample([]byte(raw))
		if err != nil {
			return nil, err
		}
		out = append(out, sample)
		size += len(raw) + 1
	}
	return out, rows.Err()
}

// Acknowledge validates the complete response before deleting anything. An
// unrelated 2xx response, partial ACK, or unknown ID cannot discard observations.
func (b *TelemetryBuffer) Acknowledge(ctx context.Context, sent []protocol.TelemetrySample, ack protocol.TelemetryAck) error {
	if len(sent) == 0 || len(ack.SampleIDs) != len(sent) {
		return errors.New("invalid telemetry acknowledgment")
	}
	ids := make(map[string]bool, len(sent))
	for _, sample := range sent {
		ids[sample.SampleID] = true
	}
	for _, id := range ack.SampleIDs {
		if !ids[id] {
			return errors.New("invalid telemetry acknowledgment")
		}
		delete(ids, id)
	}
	if len(ids) != 0 {
		return errors.New("incomplete telemetry acknowledgment")
	}
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, sample := range sent {
		payload, err := protocol.CanonicalTelemetrySample(sample)
		if err != nil {
			return err
		}
		// Compare the immutable payload too, so a stale ACK cannot delete a
		// replacement even if a caller accidentally reuses an expired ID.
		if _, err = tx.ExecContext(ctx, "DELETE FROM telemetry_buffer WHERE sample_id=? AND payload=?", sample.SampleID, string(payload)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (b *TelemetryBuffer) Hold(ctx context.Context, id, reason string) error {
	if reason != "telemetry_invalid" && reason != "telemetry_conflict" {
		return errors.New("invalid telemetry hold reason")
	}
	_, err := b.db.ExecContext(ctx, "UPDATE telemetry_buffer SET held=1,hold_reason=? WHERE sample_id=?", reason, id)
	return err
}

func (b *TelemetryBuffer) Status(ctx context.Context) (TelemetryBufferStatus, error) {
	out := TelemetryBufferStatus{MaxBytes: b.maxBytes}
	err := b.db.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(held),0),coalesce(sum(length(CAST(payload AS BLOB))),0),
(SELECT dropped_expired FROM telemetry_identity),(SELECT dropped_capacity FROM telemetry_identity) FROM telemetry_buffer`).Scan(&out.Samples, &out.HeldSamples, &out.PayloadBytes, &out.DroppedExpired, &out.DroppedCapacity)
	return out, err
}
