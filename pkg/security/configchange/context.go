// Package configchange coordinates bounded, single-resource configuration
// changes in the resource's own SQLite transaction. It has no identity store,
// packet hook or distributed transaction coordinator.
package configchange

import (
	"context"
	"database/sql"
	"errors"
)

var (
	ErrInvalid    = errors.New("invalid configuration change")
	ErrConflict   = errors.New("configuration change conflicts with current state")
	ErrLimit      = errors.New("configuration change retention limit reached")
	ErrValidation = errors.New("configuration validation completed without commit")
)

type Actor struct {
	ID string
	// Authorize rechecks current authority inside the target write transaction.
	// It must not commit the transaction or activate a runtime snapshot.
	Authorize func(context.Context, *sql.DB, *sql.Tx, string) error
}
type actorKey struct{}

func WithActor(ctx context.Context, actor Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

type operation struct {
	capture                                  *Document
	database                                 *sql.DB
	kind, stageID, newResourceID, rollbackOf string
	restoring                                bool
}
type operationKey struct{}

func operationFrom(ctx context.Context) operation {
	v, _ := ctx.Value(operationKey{}).(operation)
	return v
}
func NewResourceID(ctx context.Context, fallback string) string {
	if id := operationFrom(ctx).newResourceID; id != "" {
		return id
	}
	return fallback
}
func Restoring(ctx context.Context) bool { return operationFrom(ctx).restoring }
func WithRestoration(ctx context.Context) context.Context {
	o := operationFrom(ctx)
	o.restoring = true
	return context.WithValue(ctx, operationKey{}, o)
}

// Commit stops a validation before persistence and runtime activation. Callers
// defer Rollback as usual, so all validation-only SQL changes are discarded.
type committerKey struct{}

// Committer prepares a complete candidate, commits its marker and target in tx,
// then performs a non-failing runtime swap. Validation must leave tx uncommitted.
type Committer func(context.Context, *sql.Tx, bool) error

func WithCommitter(ctx context.Context, commit Committer) context.Context {
	return context.WithValue(ctx, committerKey{}, commit)
}
func Commit(ctx context.Context, tx *sql.Tx) error {
	if commit, ok := ctx.Value(committerKey{}).(Committer); ok {
		return commit(ctx, tx, Validating(ctx))
	}
	if operationFrom(ctx).capture != nil {
		return ErrValidation
	}
	return tx.Commit()
}

func Workflow(ctx context.Context) bool     { return operationFrom(ctx).database != nil }
func Validating(ctx context.Context) bool   { return operationFrom(ctx).capture != nil }
func RollbackOf(ctx context.Context) string { return operationFrom(ctx).rollbackOf }

// Begin revalidates the actor before modifying policy or revoking sessions in
// this transaction. Rechecking after a legitimate self-demotion/revocation
// would incorrectly reject that very change.
func Begin(ctx context.Context, db *sql.DB, kind string) (*sql.Tx, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if actor, managed := ctx.Value(actorKey{}).(Actor); managed && actor.Authorize != nil {
		if err = actor.Authorize(ctx, db, tx, kind); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
	}
	return tx, nil
}

func Managed(ctx context.Context) bool { _, ok := ctx.Value(actorKey{}).(Actor); return ok }

type checkKey struct{}

func CheckingOnly(ctx context.Context) bool { v, _ := ctx.Value(checkKey{}).(bool); return v }

// Check releases the connection before a control-path network operation.
func Check(ctx context.Context, db *sql.DB, kind string) error {
	tx, err := Begin(context.WithValue(ctx, checkKey{}, true), db, kind)
	if err != nil {
		return err
	}
	return tx.Rollback()
}
