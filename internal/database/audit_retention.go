package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

const auditSettingsSchema = `
CREATE TABLE audit_settings(id INTEGER PRIMARY KEY CHECK(id=1),capacity INTEGER NOT NULL CHECK(capacity BETWEEN 1000 AND 1000000));
INSERT INTO audit_settings(id,capacity) VALUES(1,100000);
`

const MaxAuditPruneBatch = 1000

type AuditRetentionReport struct {
	CurrentCapacity   int    `json:"current_capacity"`
	Capacity          int    `json:"capacity"`
	Rows              int    `json:"rows"`
	Eligible          int    `json:"eligible"`
	Limit             int    `json:"limit"`
	Applied           bool   `json:"applied"`
	Deleted           int    `json:"deleted"`
	RemainingEligible int    `json:"remaining_eligible"`
	Backup            string `json:"backup,omitempty"`
}

func (s *Store) PreviewAuditRetention(ctx context.Context, capacity int) (AuditRetentionReport, error) {
	p := AuditRetentionReport{Capacity: capacity, Limit: MaxAuditPruneBatch}
	if capacity != 0 && (capacity < 1000 || capacity > 1000000) {
		return p, errors.New("audit capacity must be 1000-1000000 events")
	}
	err := s.DB.QueryRowContext(ctx, "SELECT capacity,(SELECT count(*) FROM audit_events) FROM audit_settings WHERE id=1").Scan(&p.CurrentCapacity, &p.Rows)
	if err != nil {
		return p, err
	}
	if capacity == 0 {
		p.Capacity = p.CurrentCapacity
	}
	if err = s.DB.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE id <= (SELECT coalesce(max(id),0)+1 FROM audit_events)-?`, p.Capacity).Scan(&p.Eligible); err != nil {
		return p, err
	}
	p.RemainingEligible = max(0, p.Eligible-p.Limit)
	return p, nil
}

// ConfigureAuditRetention makes a verified backup before applying the selected
// capacity. Pruning is capped per audit write; lowering the capacity converges in
// bounded batches as audited activity continues. Existing defaults are retained.
func (s *Store) ConfigureAuditRetention(ctx context.Context, capacity int, backup string) (AuditRetentionReport, error) {
	p, err := s.PreviewAuditRetention(ctx, capacity)
	if err != nil {
		return p, err
	}
	if backup == "" {
		return p, errors.New("a new verified backup is required before configuring audit retention")
	}
	if err = s.Backup(ctx, backup); err != nil {
		return p, err
	}
	p.Backup = backup
	err = s.Write(ctx, func(tx *sql.Tx) error {
		var current, before int
		if err := tx.QueryRowContext(ctx, "SELECT capacity,(SELECT count(*) FROM audit_events) FROM audit_settings WHERE id=1").Scan(&current, &before); err != nil {
			return err
		}
		if current != p.CurrentCapacity {
			return errors.New("audit retention configuration changed; preview again")
		}
		if _, err := tx.ExecContext(ctx, "UPDATE audit_settings SET capacity=? WHERE id=1", p.Capacity); err != nil {
			return err
		}
		if err := Audit(ctx, tx, "local-operator", "audit.retention", "", "", fmt.Sprintf("capacity=%d", p.Capacity)); err != nil {
			return err
		}
		var after int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM audit_events").Scan(&after); err != nil {
			return err
		}
		p.Rows = before
		p.Deleted = before + 1 - after
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE id <= (SELECT max(id) FROM audit_events)-?`, p.Capacity).Scan(&p.RemainingEligible); err != nil {
			return err
		}
		return nil
	})
	p.Applied = err == nil
	return p, err
}
