package database

import (
	"context"
	"database/sql"
	"errors"
	"sort"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

const nodeMetadataSchema = `
CREATE TABLE node_tags(node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,tag TEXT NOT NULL,PRIMARY KEY(node_id,tag));
CREATE INDEX node_tags_lookup ON node_tags(tag,node_id);
CREATE TABLE node_revocations(node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,revoked_at INTEGER NOT NULL,revoked_by TEXT NOT NULL);
`

var ErrInvalidNodeTags = errors.New("invalid node tags")

func (s *Store) NodeTags(ctx context.Context, id string) ([]string, error) {
	if !identity.Valid(id) {
		return nil, ErrNotFound
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT tag FROM node_tags WHERE node_id=? ORDER BY tag", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var tag string
		if err = rows.Scan(&tag); err != nil {
			return nil, err
		}
		out = append(out, tag)
	}
	return out, rows.Err()
}

func (s *Store) SetNodeTags(ctx context.Context, actor, id string, tags []string) error {
	if !identity.Valid(id) {
		return ErrNotFound
	}
	if !protocol.ValidNodeTags(tags) {
		return ErrInvalidNodeTags
	}
	tags = append([]string{}, tags...)
	sort.Strings(tags)
	return s.Write(ctx, func(tx *sql.Tx) error {
		var exists int
		if err := tx.QueryRowContext(ctx, "SELECT 1 FROM nodes WHERE id=?", id).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM node_tags WHERE node_id=?", id); err != nil {
			return err
		}
		for _, tag := range tags {
			if _, err := tx.ExecContext(ctx, "INSERT INTO node_tags(node_id,tag) VALUES(?,?)", id, tag); err != nil {
				return err
			}
		}
		return Audit(ctx, tx, actor, "node.tags.update", id, "", "succeeded")
	})
}

// Revocation records a separate permanent administrative dimension while the
// original nodes.status remains disabled for compatibility with every existing
// identity check. Old and renewal-overlap certificates are both refused.
func (s *Store) RevokeNode(ctx context.Context, actor, id string) error {
	if !identity.Valid(id) {
		return ErrNotFound
	}
	return s.Write(ctx, func(tx *sql.Tx) error {
		var exists int
		if err := tx.QueryRowContext(ctx, "SELECT 1 FROM nodes WHERE id=?", id).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM node_revocations WHERE node_id=?", id).Scan(&exists); err != nil {
			return err
		}
		if exists != 0 {
			return nil
		}
		now := s.now().Unix()
		if _, err := tx.ExecContext(ctx, "UPDATE nodes SET status='disabled' WHERE id=?", id); err != nil {
			return err
		}
		if err := finishOutstanding(ctx, tx, id, "node_revoked", now); err != nil {
			return err
		}
		if err := closeNodeAlerts(ctx, tx, id, now, "node_revoked"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO node_revocations(node_id,revoked_at,revoked_by) VALUES(?,?,?)", id, now, actor); err != nil {
			return err
		}
		return Audit(ctx, tx, actor, "node.revoke", id, "", "succeeded")
	})
}
