package database

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

const alertsSchema = `
CREATE TABLE alert_rules (
 id TEXT PRIMARY KEY, metric TEXT NOT NULL, severity TEXT NOT NULL CHECK(severity IN ('WARNING','CRITICAL')),
 threshold REAL NOT NULL, for_seconds INTEGER NOT NULL, recovery_seconds INTEGER NOT NULL,
 enabled INTEGER NOT NULL CHECK(enabled IN (0,1))
);
INSERT INTO alert_rules VALUES
 ('cpu-critical','cpu_percent','CRITICAL',90,120,120,1),
 ('memory-critical','memory_percent','CRITICAL',95,120,120,1),
 ('disk-critical','disk_percent','CRITICAL',95,120,120,1),
 ('telemetry-missing','telemetry_missing','WARNING',180,0,120,1);
CREATE TABLE alerts (
 id TEXT PRIMARY KEY, node_id TEXT NOT NULL, rule_id TEXT NOT NULL REFERENCES alert_rules(id),
 severity TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('FIRING','RESOLVED')),
 opened_at INTEGER NOT NULL, last_observed_at INTEGER NOT NULL,
 resolved_at INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL
);
CREATE UNIQUE INDEX alerts_active ON alerts(node_id,rule_id) WHERE status='FIRING';
CREATE INDEX alerts_created ON alerts(opened_at DESC,id DESC);
CREATE INDEX alerts_node_created ON alerts(node_id,opened_at DESC,id DESC);
CREATE INDEX alerts_status_created ON alerts(status,opened_at DESC,id DESC);
CREATE INDEX alerts_node_status_created ON alerts(node_id,status,opened_at DESC,id DESC);
CREATE TABLE alert_states (
 node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
 rule_id TEXT NOT NULL REFERENCES alert_rules(id),
 last_observed_at INTEGER NOT NULL DEFAULT 0, last_sample_id TEXT NOT NULL DEFAULT '',
 breach_since INTEGER NOT NULL DEFAULT 0, recovery_since INTEGER NOT NULL DEFAULT 0,
 active_alert_id TEXT NOT NULL DEFAULT '', PRIMARY KEY(node_id,rule_id)
);
CREATE TABLE alert_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT NOT NULL REFERENCES alerts(id),
 node_id TEXT NOT NULL, rule_id TEXT NOT NULL, state TEXT NOT NULL,
 timestamp INTEGER NOT NULL, reason TEXT NOT NULL
);
CREATE INDEX alert_events_node ON alert_events(node_id,id);
CREATE INDEX alert_events_alert ON alert_events(alert_id,id);
`

var ErrInvalidAlert = errors.New("invalid alert rule or query")

type AlertRule struct {
	ID              string  `json:"id"`
	Metric          string  `json:"metric"`
	Severity        string  `json:"severity"`
	Threshold       float64 `json:"threshold"`
	ForSeconds      int     `json:"for_seconds"`
	RecoverySeconds int     `json:"recovery_seconds"`
	Enabled         bool    `json:"enabled"`
}

func (r AlertRule) Validate() error {
	if !identity.Valid(r.ID) || (r.Severity != "WARNING" && r.Severity != "CRITICAL") || math.IsNaN(r.Threshold) || math.IsInf(r.Threshold, 0) || r.ForSeconds < 0 || r.ForSeconds > 3600 || r.RecoverySeconds < 30 || r.RecoverySeconds > 3600 {
		return ErrInvalidAlert
	}
	switch r.Metric {
	case "cpu_percent", "memory_percent", "disk_percent":
		if r.Threshold <= 0 || r.Threshold > 100 {
			return ErrInvalidAlert
		}
	case "telemetry_missing":
		if r.Threshold < 180 || r.Threshold > 86400 || r.Threshold != math.Trunc(r.Threshold) {
			return ErrInvalidAlert
		}
	default:
		return ErrInvalidAlert
	}
	return nil
}

func listAlertRules(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) ([]AlertRule, error) {
	rows, err := q.QueryContext(ctx, "SELECT id,metric,severity,threshold,for_seconds,recovery_seconds,enabled FROM alert_rules ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AlertRule{}
	for rows.Next() {
		var r AlertRule
		if err = rows.Scan(&r.ID, &r.Metric, &r.Severity, &r.Threshold, &r.ForSeconds, &r.RecoverySeconds, &r.Enabled); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) ListAlertRules(ctx context.Context) ([]AlertRule, error) {
	return listAlertRules(ctx, s.DB)
}

// Rule changes reset evidence windows and explicitly resolve old incidents with
// a configuration reason. This administrative transition is never recovery
// evidence, and the new rule starts with fresh observations.
func (s *Store) PutAlertRule(ctx context.Context, actor string, r AlertRule) error {
	if err := r.Validate(); err != nil {
		return err
	}
	return s.Write(ctx, func(tx *sql.Tx) error {
		var previous AlertRule
		err := tx.QueryRowContext(ctx, "SELECT id,metric,severity,threshold,for_seconds,recovery_seconds,enabled FROM alert_rules WHERE id=?", r.ID).Scan(&previous.ID, &previous.Metric, &previous.Severity, &previous.Threshold, &previous.ForSeconds, &previous.RecoverySeconds, &previous.Enabled)
		if err == nil && previous == r {
			return nil
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var count, exists int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM alert_rules").Scan(&count); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM alert_rules WHERE id=?", r.ID).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 && count >= 32 {
			return ErrConflict
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO alert_rules(id,metric,severity,threshold,for_seconds,recovery_seconds,enabled) VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET metric=excluded.metric,severity=excluded.severity,threshold=excluded.threshold,for_seconds=excluded.for_seconds,recovery_seconds=excluded.recovery_seconds,enabled=excluded.enabled`, r.ID, r.Metric, r.Severity, r.Threshold, r.ForSeconds, r.RecoverySeconds, r.Enabled); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, "SELECT "+alertColumns+" FROM alerts WHERE rule_id=? AND status='FIRING'", r.ID)
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
		reason := "rule_changed"
		if !r.Enabled {
			reason = "rule_disabled"
		}
		for _, a := range active {
			if err := resolveAlert(ctx, tx, a.ID, a.NodeID, a.RuleID, s.now().Unix(), a.LastObservedAt, reason); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, "UPDATE alert_states SET breach_since=0,recovery_since=0,active_alert_id='' WHERE rule_id=?", r.ID); err != nil {
			return err
		}
		return auditSubject(ctx, tx, actor, "alert.rule.update", "", "", r.ID, "succeeded")
	})
}

type Alert struct {
	ID             string `json:"id"`
	NodeID         string `json:"node_id"`
	RuleID         string `json:"rule_id"`
	Severity       string `json:"severity"`
	Status         string `json:"status"`
	OpenedAt       int64  `json:"opened_at"`
	LastObservedAt int64  `json:"last_observed_at"`
	ResolvedAt     int64  `json:"resolved_at"`
	Reason         string `json:"reason"`
}

const alertColumns = "id,node_id,rule_id,severity,status,opened_at,last_observed_at,resolved_at,reason"

func scanAlert(row interface{ Scan(...any) error }) (Alert, error) {
	var a Alert
	err := row.Scan(&a.ID, &a.NodeID, &a.RuleID, &a.Severity, &a.Status, &a.OpenedAt, &a.LastObservedAt, &a.ResolvedAt, &a.Reason)
	return a, err
}

type AlertQuery struct {
	NodeID, Status, Cursor string
	Limit                  int
}
type AlertPage struct {
	Items      []Alert `json:"items"`
	NextCursor string  `json:"next_cursor,omitempty"`
}
type alertCursor struct {
	NodeID   string `json:"node_id"`
	Status   string `json:"status"`
	OpenedAt int64  `json:"opened_at"`
	ID       string `json:"id"`
}

func (q AlertQuery) cursor() (alertCursor, error) {
	var c alertCursor
	if q.NodeID != "" && !identity.Valid(q.NodeID) || q.Status != "" && q.Status != "FIRING" && q.Status != "RESOLVED" || q.Limit < 1 || q.Limit > 200 {
		return c, ErrInvalidAlert
	}
	if q.Cursor == "" {
		return c, nil
	}
	if len(q.Cursor) > 1024 {
		return c, ErrInvalidAlert
	}
	b, err := base64.RawURLEncoding.DecodeString(q.Cursor)
	if err != nil || strictjson.Decode(b, &c, 768, "node_id", "status", "opened_at", "id") != nil || c.NodeID != q.NodeID || c.Status != q.Status || c.OpenedAt <= 0 || !identity.Valid(c.ID) {
		return c, ErrInvalidAlert
	}
	return c, nil
}
func (q AlertQuery) Validate() error { _, err := q.cursor(); return err }

func (s *Store) QueryAlerts(ctx context.Context, q AlertQuery) (AlertPage, error) {
	p := AlertPage{Items: []Alert{}}
	c, err := q.cursor()
	if err != nil {
		return p, err
	}
	where := "1=1"
	args := []any{}
	if q.NodeID != "" {
		where += " AND node_id=?"
		args = append(args, q.NodeID)
	}
	if q.Status != "" {
		where += " AND status=?"
		args = append(args, q.Status)
	}
	if q.Cursor != "" {
		where += " AND (opened_at,id)<(?,?)"
		args = append(args, c.OpenedAt, c.ID)
	}
	args = append(args, q.Limit+1)
	rows, err := s.DB.QueryContext(ctx, "SELECT "+alertColumns+" FROM alerts WHERE "+where+" ORDER BY opened_at DESC,id DESC LIMIT ?", args...)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		a, e := scanAlert(rows)
		if e != nil {
			return p, e
		}
		p.Items = append(p.Items, a)
	}
	if err = rows.Err(); err != nil {
		return p, err
	}
	if len(p.Items) > q.Limit {
		p.Items = p.Items[:q.Limit]
		last := p.Items[len(p.Items)-1]
		b, _ := json.Marshal(alertCursor{q.NodeID, q.Status, last.OpenedAt, last.ID})
		p.NextCursor = base64.RawURLEncoding.EncodeToString(b)
	}
	return p, nil
}

type AlertEvent struct {
	ID        int64  `json:"id"`
	AlertID   string `json:"alert_id"`
	NodeID    string `json:"node_id"`
	RuleID    string `json:"rule_id"`
	State     string `json:"state"`
	Timestamp int64  `json:"timestamp"`
	Reason    string `json:"reason"`
}
type AlertEventQuery struct {
	NodeID, AlertID string
	After           int64
	Limit           int
}

func (q AlertEventQuery) Validate() error {
	if q.NodeID != "" && !identity.Valid(q.NodeID) || q.AlertID != "" && !identity.Valid(q.AlertID) || q.After < 0 || q.Limit < 1 || q.Limit > 200 {
		return ErrInvalidAlert
	}
	return nil
}

func (s *Store) QueryAlertEvents(ctx context.Context, q AlertEventQuery) ([]AlertEvent, error) {
	if err := q.Validate(); err != nil {
		return nil, err
	}
	where := "id>?"
	args := []any{q.After}
	if q.NodeID != "" {
		where += " AND node_id=?"
		args = append(args, q.NodeID)
	}
	if q.AlertID != "" {
		where += " AND alert_id=?"
		args = append(args, q.AlertID)
	}
	args = append(args, q.Limit)
	rows, err := s.DB.QueryContext(ctx, "SELECT id,alert_id,node_id,rule_id,state,timestamp,reason FROM alert_events WHERE "+where+" ORDER BY id LIMIT ?", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AlertEvent{}
	for rows.Next() {
		var e AlertEvent
		if err = rows.Scan(&e.ID, &e.AlertID, &e.NodeID, &e.RuleID, &e.State, &e.Timestamp, &e.Reason); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AlertNotifier is an integration boundary, not an enabled notification channel.
// Consumers checkpoint event IDs only after successful delivery. An event ID is
// the idempotency key; retries can deliver the same event more than once.
type AlertNotifier interface {
	Notify(context.Context, AlertEvent) error
}

func (s *Store) DeliverAlertEvents(ctx context.Context, after int64, limit int, notifier AlertNotifier) (int64, error) {
	if notifier == nil {
		return after, ErrInvalidAlert
	}
	events, err := s.QueryAlertEvents(ctx, AlertEventQuery{After: after, Limit: limit})
	if err != nil {
		return after, err
	}
	for _, event := range events {
		if err = notifier.Notify(ctx, event); err != nil {
			return after, err
		}
		after = event.ID
	}
	return after, nil
}
