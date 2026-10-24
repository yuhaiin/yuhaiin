package configchange

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strconv"
	"time"
	"uuid"
)

// Each database owns its stages and history. Actor IDs are attribution only;
// private authentication records stay in their owning store. Private rollback
// payloads are never returned by APIs.
var SchemaStatements = []string{
	`CREATE TABLE configuration_changes(id TEXT PRIMARY KEY,kind TEXT NOT NULL,resource_id TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('staged','committed')),origin TEXT NOT NULL,created_by TEXT NOT NULL,committed_by TEXT NOT NULL,created_at INTEGER NOT NULL,committed_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,revision TEXT NOT NULL,rollback_of TEXT NOT NULL,before_json TEXT NOT NULL,after_json TEXT NOT NULL,diff_json TEXT NOT NULL)`,
	`CREATE INDEX configuration_changes_recent ON configuration_changes(state,created_at DESC,id DESC)`,
	`CREATE INDEX configuration_changes_resource ON configuration_changes(kind,resource_id,created_at DESC)`,
}

const (
	MaxPayload = 512 << 10
	MaxStages  = 32
	MaxHistory = 128
)

type Document struct {
	Kind, ResourceID, Revision string
	Before, After              jsontext.Value
	Diff                       jsontext.Value
}

func NewDocument(kind, id string, revision uint64, before, after, publicBefore, publicAfter any) (Document, error) {
	d := Document{Kind: kind, ResourceID: id, Revision: strconv.FormatUint(revision, 10)}
	var err error
	d.Before, err = json.Marshal(before, json.Deterministic(true))
	if err != nil {
		return d, err
	}
	d.After, err = json.Marshal(after, json.Deterministic(true))
	if err != nil {
		return d, err
	}
	if len(d.Before) > MaxPayload || len(d.After) > MaxPayload {
		return d, ErrLimit
	}
	d.Diff, err = json.Marshal(struct {
		Before any `json:"before"`
		After  any `json:"after"`
	}{publicBefore, publicAfter}, json.Deterministic(true))
	if err != nil {
		return d, err
	}
	if len(d.Diff) > 2*MaxPayload {
		return d, ErrLimit
	}
	return d, nil
}

type Change struct {
	ID          string         `json:"id"`
	Kind        string         `json:"kind"`
	ResourceID  string         `json:"resourceId"`
	State       string         `json:"state"`
	Origin      string         `json:"origin"`
	CreatedBy   string         `json:"createdBy"`
	CommittedBy string         `json:"committedBy"`
	CreatedAt   int64          `json:"createdAt"`
	CommittedAt int64          `json:"committedAt"`
	ExpiresAt   int64          `json:"expiresAt"`
	Revision    string         `json:"revision"`
	RollbackOf  string         `json:"rollbackOf"`
	Diff        jsontext.Value `json:"diff"`
}

const metadataColumns = `id,kind,resource_id,state,origin,created_by,committed_by,created_at,committed_at,expires_at,revision,rollback_of`
const columns = metadataColumns + `,diff_json`

type scanner interface{ Scan(...any) error }

func scanChange(row scanner) (Change, error) {
	var c Change
	var diff string
	err := row.Scan(&c.ID, &c.Kind, &c.ResourceID, &c.State, &c.Origin, &c.CreatedBy, &c.CommittedBy, &c.CreatedAt, &c.CommittedAt, &c.ExpiresAt, &c.Revision, &c.RollbackOf, &diff)
	c.Diff = jsontext.Value(diff)
	return c, err
}

type Journal struct{ db *sql.DB }

func New(db *sql.DB) *Journal        { return &Journal{db: db} }
func (j *Journal) Database() *sql.DB { return j.db }
func (j *Journal) Get(ctx context.Context, id string) (Change, error) {
	return scanChange(j.db.QueryRowContext(ctx, `SELECT `+columns+` FROM configuration_changes WHERE id=?`, id))
}
func (j *Journal) List(ctx context.Context) ([]Change, error) {
	rows, err := j.db.QueryContext(ctx, `SELECT `+metadataColumns+","+`'null' FROM configuration_changes WHERE state='committed' OR expires_at>? ORDER BY created_at DESC,id DESC LIMIT ?`, time.Now().UnixMilli(), MaxStages+MaxHistory)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Change{}
	for rows.Next() {
		c, err := scanChange(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Payload is exclusively for trusted adapters, after kind-specific permission
// checks. It is not an HTTP response type.
func (j *Journal) Payload(ctx context.Context, id string) (Document, error) {
	var d Document
	var before, after, diff string
	err := j.db.QueryRowContext(ctx, `SELECT kind,resource_id,revision,before_json,after_json,diff_json FROM configuration_changes WHERE id=?`, id).Scan(&d.Kind, &d.ResourceID, &d.Revision, &before, &after, &diff)
	d.Before = jsontext.Value(before)
	d.After = jsontext.Value(after)
	d.Diff = jsontext.Value(diff)
	return d, err
}
func prune(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM configuration_changes WHERE state='staged' AND expires_at<=?`, time.Now().UnixMilli()); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM configuration_changes WHERE id IN(SELECT id FROM configuration_changes WHERE state='committed' ORDER BY committed_at DESC,id DESC LIMIT -1 OFFSET ?)`, MaxHistory)
	return err
}
func insert(ctx context.Context, tx *sql.Tx, c Change, d Document) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO configuration_changes(id,kind,resource_id,state,origin,created_by,committed_by,created_at,committed_at,expires_at,revision,rollback_of,before_json,after_json,diff_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, c.ID, d.Kind, d.ResourceID, c.State, c.Origin, c.CreatedBy, c.CommittedBy, c.CreatedAt, c.CommittedAt, c.ExpiresAt, d.Revision, c.RollbackOf, string(d.Before), string(d.After), string(d.Diff))
	return err
}

// Record must be called after validation, before Commit, with the exact before
// and resolved after values from that same transaction. Public metadata must
// omit secrets; the private documents remain only in this database.
func Record(ctx context.Context, db *sql.DB, tx *sql.Tx, d Document) error {
	actor, managed := ctx.Value(actorKey{}).(Actor)
	if !managed {
		return nil
	}
	if actor.ID == "" || d.Kind == "" || d.ResourceID == "" {
		return ErrInvalid
	}
	o := operationFrom(ctx)
	if o.database != nil && (o.database != db || o.kind != d.Kind) {
		return ErrInvalid
	}
	if o.capture != nil {
		if o.capture.Kind != "" {
			return ErrInvalid
		}
		*o.capture = d
		return nil
	}
	now := time.Now().UnixMilli()
	if o.stageID != "" {
		var before, kind, id string
		var expires int64
		err := tx.QueryRowContext(ctx, `SELECT kind,resource_id,before_json,expires_at FROM configuration_changes WHERE id=? AND state='staged'`, o.stageID).Scan(&kind, &id, &before, &expires)
		if err != nil {
			return ErrConflict
		}
		if kind != d.Kind || id != d.ResourceID || expires <= now || !bytes.Equal([]byte(before), d.Before) {
			return ErrConflict
		}
		result, err := tx.ExecContext(ctx, `UPDATE configuration_changes SET state='committed',committed_by=?,committed_at=?,revision=?,after_json=?,diff_json=? WHERE id=? AND state='staged'`, actor.ID, now, d.Revision, string(d.After), string(d.Diff), o.stageID)
		if err != nil {
			return err
		}
		if n, _ := result.RowsAffected(); n != 1 {
			return ErrConflict
		}
	} else {
		c := Change{ID: uuid.New().String(), State: "committed", Origin: "direct", CreatedBy: actor.ID, CommittedBy: actor.ID, CreatedAt: now, CommittedAt: now}
		if err := insert(ctx, tx, c, d); err != nil {
			return err
		}
	}
	return prune(ctx, tx)
}

// RecordValues skips all serialization and history limits when the optional
// managed actor is absent (including native/local-only deployments).
func RecordValues(ctx context.Context, db *sql.DB, tx *sql.Tx, kind, id string, revision uint64, before, after, publicBefore, publicAfter any) error {
	if _, managed := ctx.Value(actorKey{}).(Actor); !managed {
		return nil
	}
	d, err := NewDocument(kind, id, revision, before, after, publicBefore, publicAfter)
	if err != nil {
		return err
	}
	return Record(ctx, db, tx, d)
}
