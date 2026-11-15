package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
)

const MaxTelemetryPruneBatches = 100

type TelemetryPruneItem struct {
	ID            int64  `json:"id"`
	NodeID        string `json:"node_id"`
	SampleID      string `json:"sample_id"`
	ObservedAt    int64  `json:"observed_at"`
	ReceivedAt    int64  `json:"received_at"`
	PayloadSHA256 string `json:"payload_sha256"`
}

type TelemetryPruneReport struct {
	RetainDays       int                  `json:"retain_days"`
	Cutoff           int64                `json:"cutoff"`
	Limit            int                  `json:"limit"`
	Batches          int                  `json:"batches"`
	Items            []TelemetryPruneItem `json:"items"`
	Applied          bool                 `json:"applied"`
	Deleted          int                  `json:"deleted"`
	Backup           string               `json:"backup,omitempty"`
	SweepID          string               `json:"sweep_id,omitempty"`
	CompletedBatches int                  `json:"completed_batches"`
	FailedBatch      int                  `json:"failed_batch,omitempty"`
	BackupDurationMS int64                `json:"backup_duration_ms,omitempty"`
	PruneDurationMS  int64                `json:"prune_duration_ms,omitempty"`
}

func (s *Store) PreviewPruneTelemetry(ctx context.Context, retainDays, limit int) (TelemetryPruneReport, error) {
	return s.PreviewPruneTelemetrySweep(ctx, retainDays, limit, 1)
}

// PreviewPruneTelemetrySweep freezes the entire bounded candidate list before
// backup. Later inserts cannot join the sweep, even if their observation is old.
func (s *Store) PreviewPruneTelemetrySweep(ctx context.Context, retainDays, limit, batches int) (TelemetryPruneReport, error) {
	p := TelemetryPruneReport{RetainDays: retainDays, Limit: limit, Batches: batches, Items: []TelemetryPruneItem{}}
	if retainDays < 1 || retainDays > 36500 || limit < 1 || limit > MaxPruneBatch || batches < 1 || batches > MaxTelemetryPruneBatches {
		return p, errors.New("retention must be 1-36500 days, batch limit 1-1000 and batches 1-100")
	}
	p.Cutoff = s.now().Add(-time.Duration(retainDays) * 24 * time.Hour).Unix()
	rows, err := s.DB.QueryContext(ctx, "SELECT id,node_id,sample_id,observed_at,received_at,payload_json FROM telemetry_samples WHERE observed_at<? ORDER BY observed_at,id LIMIT ?", p.Cutoff, limit*batches)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var item TelemetryPruneItem
		var payload []byte
		if err = rows.Scan(&item.ID, &item.NodeID, &item.SampleID, &item.ObservedAt, &item.ReceivedAt, &payload); err != nil {
			return p, err
		}
		hash := sha256.Sum256(payload)
		item.PayloadSHA256 = hex.EncodeToString(hash[:])
		p.Items = append(p.Items, item)
	}
	return p, rows.Err()
}

// PruneTelemetry removes a bounded, previewed observation-time batch only
// after a verified backup. It never prunes diagnostic or identity state.
func (s *Store) PruneTelemetry(ctx context.Context, retainDays, limit int, backup string) (TelemetryPruneReport, error) {
	return s.PruneTelemetrySweep(ctx, retainDays, limit, 1, backup)
}

// PruneTelemetrySweep makes one verified backup for the frozen list, then
// commits at most batches short transactions of at most limit observations.
// Errors return accurate committed progress; only the failed batch rolls back.
func (s *Store) PruneTelemetrySweep(ctx context.Context, retainDays, limit, batches int, backup string) (TelemetryPruneReport, error) {
	p, err := s.PreviewPruneTelemetrySweep(ctx, retainDays, limit, batches)
	if err != nil {
		return p, err
	}
	if backup == "" {
		return p, errors.New("a new backup path is required before telemetry pruning")
	}
	absBackup, err := filepath.Abs(backup)
	if err != nil {
		return p, err
	}
	p.SweepID = identity.RandomID()
	// Audit exports bound status fields to 1,024 bytes. Validate the longest
	// possible summary before creating a backup or committing any deletion.
	if _, err = telemetryPruneAudit(p.Cutoff, p.SweepID, absBackup, batches, limit); err != nil {
		return p, err
	}
	started := time.Now()
	if err = s.Backup(ctx, backup); err != nil {
		p.BackupDurationMS = time.Since(started).Milliseconds()
		return p, err
	}
	p.Backup = backup
	// The snapshot must contain every frozen candidate. Another maintenance
	// process can delete and reinsert rows while the backup is being made; a
	// matching live row alone cannot prove that this backup covers its deletion.
	if err = verifyTelemetryPruneSnapshot(ctx, absBackup, p.Cutoff, p.Items); err != nil {
		p.BackupDurationMS = time.Since(started).Milliseconds()
		return p, err
	}
	p.BackupDurationMS = time.Since(started).Milliseconds()
	started = time.Now()
	for offset := 0; offset < len(p.Items); offset += limit {
		items := p.Items[offset:min(offset+limit, len(p.Items))]
		batch := p.CompletedBatches + 1
		err = s.Write(ctx, func(tx *sql.Tx) error {
			return pruneTelemetryBatch(ctx, tx, p.Cutoff, p.SweepID, absBackup, batch, items)
		})
		if err != nil {
			p.FailedBatch = batch
			p.PruneDurationMS = time.Since(started).Milliseconds()
			return p, fmt.Errorf("telemetry sweep stopped at batch %d after %d committed batches and %d deleted samples: %w", batch, p.CompletedBatches, p.Deleted, err)
		}
		p.CompletedBatches++
		p.Deleted += len(items)
	}
	p.PruneDurationMS = time.Since(started).Milliseconds()
	p.Applied = true
	return p, nil
}

func pruneTelemetryBatch(ctx context.Context, tx *sql.Tx, cutoff int64, sweepID, backup string, batch int, items []TelemetryPruneItem) error {
	for _, item := range items {
		// SQLite may reuse a deleted INTEGER PRIMARY KEY. Another maintenance
		// process followed by delayed re-upload must not substitute new content
		// under a frozen ID, even when both receipts occur in the same second.
		var received int64
		var payload []byte
		err := tx.QueryRowContext(ctx, "SELECT received_at,payload_json FROM telemetry_samples WHERE id=? AND node_id=? AND sample_id=? AND observed_at=? AND observed_at<?", item.ID, item.NodeID, item.SampleID, item.ObservedAt, cutoff).Scan(&received, &payload)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrConflict
		}
		if err != nil {
			return err
		}
		hash := sha256.Sum256(payload)
		if received != item.ReceivedAt || hex.EncodeToString(hash[:]) != item.PayloadSHA256 {
			return ErrConflict
		}
		if err := updateOne(ctx, tx, "DELETE FROM telemetry_samples WHERE id=? AND node_id=? AND sample_id=? AND observed_at=? AND received_at=? AND observed_at<?", item.ID, item.NodeID, item.SampleID, item.ObservedAt, item.ReceivedAt, cutoff); err != nil {
			return err
		}
	}
	// One audit record links a committed batch to its frozen report and verified
	// backup. Per-sample cleanup must not evict security audit history at fleet scale.
	details, err := telemetryPruneAudit(cutoff, sweepID, backup, batch, len(items))
	if err != nil {
		return err
	}
	return auditSubject(ctx, tx, "local-operator", "telemetry.prune", "", "", sweepID, details)
}

func verifyTelemetryPruneSnapshot(ctx context.Context, path string, cutoff int64, items []TelemetryPruneItem) error {
	uriPath := filepath.ToSlash(path)
	if runtime.GOOS == "windows" {
		uriPath = "/" + uriPath
	}
	uri := url.URL{Scheme: "file", Path: uriPath, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	stmt, err := db.PrepareContext(ctx, "SELECT received_at,payload_json FROM telemetry_samples WHERE id=? AND node_id=? AND sample_id=? AND observed_at=? AND observed_at<?")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, item := range items {
		var received int64
		var payload []byte
		err := stmt.QueryRowContext(ctx, item.ID, item.NodeID, item.SampleID, item.ObservedAt, cutoff).Scan(&received, &payload)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("telemetry candidate is missing from the verified backup: %w", ErrConflict)
		}
		if err != nil {
			return err
		}
		hash := sha256.Sum256(payload)
		if received != item.ReceivedAt || hex.EncodeToString(hash[:]) != item.PayloadSHA256 {
			return fmt.Errorf("telemetry candidate differs from the verified backup: %w", ErrConflict)
		}
	}
	return nil
}

func telemetryPruneAudit(cutoff int64, sweepID, backup string, batch, count int) (string, error) {
	details, err := json.Marshal(struct {
		SweepID string `json:"sweep_id"`
		Batch   int    `json:"batch"`
		Cutoff  int64  `json:"cutoff"`
		Count   int    `json:"count"`
		Backup  string `json:"backup"`
	}{sweepID, batch, cutoff, count, backup})
	if err != nil {
		return "", err
	}
	if len(details) > 1024 {
		return "", errors.New("backup path is too long for the bounded telemetry audit record")
	}
	return string(details), nil
}
