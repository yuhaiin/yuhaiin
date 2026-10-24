package configchange

import (
	"context"
	"errors"
	"time"
	"uuid"
)

// Apply reuses the owning module's existing mutation/compile pipeline. During
// validation Commit returns ErrValidation and the module rolls its SQL back.
type Apply func(context.Context) error

func (j *Journal) Stage(ctx context.Context, kind, plannedID, rollbackOf string, apply Apply) (Change, error) {
	actor, ok := ctx.Value(actorKey{}).(Actor)
	if !ok || actor.ID == "" {
		return Change{}, ErrInvalid
	}
	var d Document
	validation := context.WithValue(ctx, operationKey{}, operation{capture: &d, database: j.db, kind: kind, newResourceID: plannedID, rollbackOf: rollbackOf})
	if err := apply(validation); !errors.Is(err, ErrValidation) {
		if err == nil {
			err = ErrInvalid
		}
		return Change{}, err
	}
	if d.Kind != kind || d.ResourceID == "" {
		return Change{}, ErrInvalid
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return Change{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if actor.Authorize != nil {
		if err = actor.Authorize(validation, j.db, tx, kind); err != nil {
			return Change{}, err
		}
	}
	if err = prune(ctx, tx); err != nil {
		return Change{}, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM configuration_changes WHERE state='staged'`).Scan(&count); err != nil {
		return Change{}, err
	}
	if count >= MaxStages {
		return Change{}, ErrLimit
	}
	now := time.Now().UnixMilli()
	c := Change{ID: uuid.New().String(), Kind: kind, ResourceID: d.ResourceID, State: "staged", Origin: "staged", CreatedBy: actor.ID, CreatedAt: now, ExpiresAt: now + int64((24*time.Hour)/time.Millisecond), Revision: d.Revision, RollbackOf: rollbackOf, Diff: d.Diff}
	if rollbackOf != "" {
		c.Origin = "rollback"
	}
	if err = insert(ctx, tx, c, d); err != nil {
		return Change{}, err
	}
	if err = tx.Commit(); err != nil {
		return Change{}, err
	}
	return c, nil
}
func (j *Journal) Validate(ctx context.Context, id string, apply Apply) error {
	c, err := j.Get(ctx, id)
	if err != nil {
		return err
	}
	if c.State != "staged" || c.ExpiresAt <= time.Now().UnixMilli() {
		return ErrConflict
	}
	d, err := j.Payload(ctx, id)
	if err != nil {
		return err
	}
	var captured Document
	ctx = context.WithValue(ctx, operationKey{}, operation{capture: &captured, database: j.db, kind: c.Kind, newResourceID: c.ResourceID, rollbackOf: c.RollbackOf})
	if err = apply(ctx); !errors.Is(err, ErrValidation) {
		if err == nil {
			err = ErrInvalid
		}
		return err
	}
	if string(d.Before) != string(captured.Before) {
		return ErrConflict
	}
	return nil
}
func (j *Journal) Commit(ctx context.Context, id string, apply Apply) (Change, error) {
	c, err := j.Get(ctx, id)
	if err != nil {
		return Change{}, err
	}
	if c.State != "staged" || c.ExpiresAt <= time.Now().UnixMilli() {
		return Change{}, ErrConflict
	}
	ctx = context.WithValue(ctx, operationKey{}, operation{database: j.db, kind: c.Kind, stageID: id, newResourceID: c.ResourceID, rollbackOf: c.RollbackOf})
	if err = apply(ctx); err != nil {
		return Change{}, err
	}
	out, err := j.Get(ctx, id)
	if err == nil && out.State != "committed" {
		return Change{}, ErrInvalid
	}
	return out, err
}

// Discard only removes uncommitted drafts. Committed history expires through
// the bounded history policy and cannot be rewritten through this API.
func (j *Journal) Discard(ctx context.Context, id string) error {
	c, err := j.Get(ctx, id)
	if err != nil {
		return err
	}
	ctx = context.WithValue(ctx, operationKey{}, operation{database: j.db, kind: c.Kind})
	tx, err := Begin(ctx, j.db, c.Kind)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `DELETE FROM configuration_changes WHERE id=? AND state='staged'`, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return ErrConflict
	}
	return tx.Commit()
}
