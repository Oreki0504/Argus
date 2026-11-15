package database

import (
	"context"
	"database/sql"
	"errors"
	"sort"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

type alertState struct {
	LastObservedAt             int64
	LastSampleID               string
	BreachSince, RecoverySince int64
	ActiveAlertID              string
}

func loadAlertState(ctx context.Context, tx *sql.Tx, node, rule string) (alertState, error) {
	var state alertState
	err := tx.QueryRowContext(ctx, "SELECT last_observed_at,last_sample_id,breach_since,recovery_since,active_alert_id FROM alert_states WHERE node_id=? AND rule_id=?", node, rule).Scan(&state.LastObservedAt, &state.LastSampleID, &state.BreachSince, &state.RecoverySince, &state.ActiveAlertID)
	if errors.Is(err, sql.ErrNoRows) {
		return state, nil
	}
	return state, err
}
func saveAlertState(ctx context.Context, tx *sql.Tx, node, rule string, state alertState) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO alert_states(node_id,rule_id,last_observed_at,last_sample_id,breach_since,recovery_since,active_alert_id) VALUES(?,?,?,?,?,?,?) ON CONFLICT(node_id,rule_id) DO UPDATE SET last_observed_at=excluded.last_observed_at,last_sample_id=excluded.last_sample_id,breach_since=excluded.breach_since,recovery_since=excluded.recovery_since,active_alert_id=excluded.active_alert_id`, node, rule, state.LastObservedAt, state.LastSampleID, state.BreachSince, state.RecoverySince, state.ActiveAlertID)
	return err
}

func alertEvent(ctx context.Context, tx *sql.Tx, id, node, rule, state string, now int64, reason string) error {
	if _, err := tx.ExecContext(ctx, "INSERT INTO alert_events(alert_id,node_id,rule_id,state,timestamp,reason) VALUES(?,?,?,?,?,?)", id, node, rule, state, now, reason); err != nil {
		return err
	}
	return auditSubject(ctx, tx, "health-evaluator", "alert."+map[string]string{"FIRING": "firing", "RESOLVED": "resolved"}[state], node, "", id, reason)
}
func resolveAlert(ctx context.Context, tx *sql.Tx, id, node, rule string, now, observed int64, reason string) error {
	if err := updateOne(ctx, tx, "UPDATE alerts SET status='RESOLVED',resolved_at=?,last_observed_at=max(last_observed_at,?),reason=? WHERE id=? AND status='FIRING'", now, observed, reason, id); err != nil {
		return err
	}
	return alertEvent(ctx, tx, id, node, rule, "RESOLVED", now, reason)
}

func closeNodeAlerts(ctx context.Context, tx *sql.Tx, node string, now int64, reason string) error {
	rows, err := tx.QueryContext(ctx, "SELECT "+alertColumns+" FROM alerts WHERE node_id=? AND status='FIRING'", node)
	if err != nil {
		return err
	}
	active := []Alert{}
	for rows.Next() {
		a, e := scanAlert(rows)
		if e != nil {
			rows.Close()
			return e
		}
		active = append(active, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, a := range active {
		if err = resolveAlert(ctx, tx, a.ID, node, a.RuleID, now, a.LastObservedAt, reason); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, "UPDATE alert_states SET active_alert_id='',breach_since=0,recovery_since=0 WHERE node_id=?", node)
	return err
}

func applyAlertEvidence(ctx context.Context, tx *sql.Tx, node string, rule AlertRule, state *alertState, known, breached bool, evidenceAt, now int64, reason string) error {
	if !known {
		state.BreachSince = 0
		state.RecoverySince = 0
		return nil
	}
	if breached {
		state.RecoverySince = 0
		if state.BreachSince == 0 {
			state.BreachSince = evidenceAt
		}
		if state.ActiveAlertID != "" {
			_, err := tx.ExecContext(ctx, "UPDATE alerts SET last_observed_at=max(last_observed_at,?) WHERE id=?", evidenceAt, state.ActiveAlertID)
			return err
		}
		if evidenceAt-state.BreachSince < int64(rule.ForSeconds) {
			return nil
		}
		state.ActiveAlertID = identity.RandomID()
		if _, err := tx.ExecContext(ctx, "INSERT INTO alerts(id,node_id,rule_id,severity,status,opened_at,last_observed_at,resolved_at,reason) VALUES(?,?,?,?,'FIRING',?,?,0,?)", state.ActiveAlertID, node, rule.ID, rule.Severity, now, evidenceAt, reason); err != nil {
			return err
		}
		return alertEvent(ctx, tx, state.ActiveAlertID, node, rule.ID, "FIRING", now, reason)
	}
	state.BreachSince = 0
	if state.ActiveAlertID == "" {
		state.RecoverySince = 0
		return nil
	}
	if state.RecoverySince == 0 {
		state.RecoverySince = evidenceAt
	}
	if evidenceAt-state.RecoverySince < int64(rule.RecoverySeconds) {
		return nil
	}
	if err := resolveAlert(ctx, tx, state.ActiveAlertID, node, rule.ID, now, evidenceAt, "valid_observations_recovered"); err != nil {
		return err
	}
	state.ActiveAlertID = ""
	state.RecoverySince = 0
	return nil
}

func metricEvidence(sample protocol.TelemetrySample, metric string) (float64, bool) {
	switch metric {
	case "cpu_percent":
		return sample.Metrics.CPU.BusyPercent, sample.Metrics.CPU.Available
	case "memory_percent":
		if sample.Metrics.Memory.Available && sample.Metrics.Memory.TotalBytes > 0 {
			return 100 * (1 - float64(sample.Metrics.Memory.AvailableBytes)/float64(sample.Metrics.Memory.TotalBytes)), true
		}
	case "disk_percent":
		value := float64(0)
		complete := len(sample.Metrics.Disks) > 0
		for _, disk := range sample.Metrics.Disks {
			if !disk.Available || disk.TotalBytes == 0 {
				complete = false
				continue
			}
			value = max(value, 100*(1-float64(disk.AvailableBytes)/float64(disk.TotalBytes)))
		}
		// Partial disks can prove a breach, but cannot prove recovery. The
		// caller checks a threshold separately when coverage is incomplete.
		return value, complete
	case "telemetry_missing":
		return 0, true
	}
	return 0, false
}

func evaluateTelemetryAlerts(ctx context.Context, tx *sql.Tx, node string, samples []protocol.TelemetrySample, now int64) error {
	if len(samples) == 0 {
		return nil
	}
	rules, err := listAlertRules(ctx, tx)
	if err != nil {
		return err
	}
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].ObservedAt == samples[j].ObservedAt {
			return samples[i].SampleID < samples[j].SampleID
		}
		return samples[i].ObservedAt < samples[j].ObservedAt
	})
	for _, sample := range samples {
		// Delayed/out-of-order delivery remains queryable; it cannot retroactively
		// open incidents or use historical good data to resolve current ones.
		gap := int64(max(180, 3*sample.IntervalSeconds))
		if sample.ObservedAt > now || now-sample.ObservedAt > gap {
			continue
		}
		for _, rule := range rules {
			if !rule.Enabled {
				continue
			}
			state, err := loadAlertState(ctx, tx, node, rule.ID)
			if err != nil {
				return err
			}
			if sample.ObservedAt <= state.LastObservedAt {
				continue
			}
			if state.LastObservedAt > 0 && sample.ObservedAt-state.LastObservedAt > gap {
				state.BreachSince = 0
				state.RecoverySince = 0
			}
			value, known := metricEvidence(sample, rule.Metric)
			breached := value >= rule.Threshold
			if rule.Metric == "disk_percent" && breached {
				known = true
			}
			if rule.Metric == "telemetry_missing" {
				known = true
				breached = false
			}
			if err = applyAlertEvidence(ctx, tx, node, rule, &state, known, breached, sample.ObservedAt, now, "threshold_sustained"); err != nil {
				return err
			}
			state.LastObservedAt = sample.ObservedAt
			state.LastSampleID = sample.SampleID
			if err = saveAlertState(ctx, tx, node, rule.ID, state); err != nil {
				return err
			}
		}
	}
	return nil
}

// SweepAlerts detects missing telemetry without waiting for an upload. Nodes
// are paginated and evaluated in separate short transactions; heartbeat and
// diagnostic writers are not held behind one fleet-wide transaction.
func (s *Store) SweepAlerts(ctx context.Context) error {
	after := ""
	for {
		rows, err := s.DB.QueryContext(ctx, "SELECT id FROM nodes WHERE id>? AND status='active' ORDER BY id LIMIT 200", after)
		if err != nil {
			return err
		}
		ids := []string{}
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, id := range ids {
			if err = s.sweepNodeAlerts(ctx, id); err != nil {
				return err
			}
			after = id
		}
		if len(ids) < 200 {
			return nil
		}
	}
}

func (s *Store) sweepNodeAlerts(ctx context.Context, node string) error {
	return s.Write(ctx, func(tx *sql.Tx) error {
		now := s.now().Unix()
		var created int64
		var status string
		if err := tx.QueryRowContext(ctx, "SELECT created_at,status FROM nodes WHERE id=?", node).Scan(&created, &status); errors.Is(err, sql.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
		if status != "active" {
			return nil
		}
		latest, err := scanTelemetry(tx.QueryRowContext(ctx, "SELECT "+telemetryColumns+" FROM telemetry_samples WHERE node_id=? AND clock_skew=0 AND observed_at<=? ORDER BY observed_at DESC,sample_id DESC LIMIT 1", node, now))
		missing := errors.Is(err, sql.ErrNoRows)
		if err != nil && !missing {
			return err
		}
		last := created
		interval := 60
		if !missing {
			last = latest.ObservedAt
			interval = latest.IntervalSeconds
		}
		rules, err := listAlertRules(ctx, tx)
		if err != nil {
			return err
		}
		for _, rule := range rules {
			if !rule.Enabled {
				continue
			}
			state, err := loadAlertState(ctx, tx, node, rule.ID)
			if err != nil {
				return err
			}
			gap := int64(max(180, 3*interval))
			if rule.Metric != "telemetry_missing" {
				if now-last > gap {
					state.BreachSince = 0
					state.RecoverySince = 0
					if err = saveAlertState(ctx, tx, node, rule.ID, state); err != nil {
						return err
					}
				}
				continue
			}
			threshold := max(int64(rule.Threshold), gap)
			if now-last < threshold {
				continue
			} // Recovery advances only on a new valid sample.
			if state.BreachSince == 0 {
				state.BreachSince = last + threshold
			}
			if err = applyAlertEvidence(ctx, tx, node, rule, &state, true, true, now, now, "telemetry_missing"); err != nil {
				return err
			}
			if err = saveAlertState(ctx, tx, node, rule.ID, state); err != nil {
				return err
			}
		}
		return nil
	})
}
