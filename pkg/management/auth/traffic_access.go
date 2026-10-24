package auth

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"github.com/Asutorufa/yuhaiin/pkg/security/configchange"
	"slices"
	"strconv"
	"sync"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/access"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/accesscontrol"
)

// AccessPolicies serializes persistence and publication together. A later saved
// revision cannot be overwritten by an earlier publisher. All fallible compile,
// reference checks and durable audit work finishes before runtime activation.
type AccessPolicies struct {
	mu         sync.Mutex
	store      *Store
	Controller *accesscontrol.Controller
}

type AccessValidation struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors"`
}

func NewAccessPolicies(ctx context.Context, store *Store) (*AccessPolicies, error) {
	service := &AccessPolicies{store: store, Controller: accesscontrol.New()}
	var data string
	var revision uint64
	err := store.db.QueryRowContext(ctx, `SELECT revision,data FROM traffic_access_config WHERE id=1`).Scan(&revision, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return service, nil
	}
	if err != nil {
		return nil, err
	}
	var config contract.Config
	if err := json.Unmarshal([]byte(data), &config, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("load access policy: %w", err)
	}
	if config.Revision != revision {
		return nil, errors.New("access policy revision is inconsistent")
	}
	prepared, err := accesscontrol.Prepare(config)
	if err != nil {
		return nil, fmt.Errorf("load access policy: %w", err)
	}
	service.Controller.Activate(prepared)
	return service, nil
}

func (a *AccessPolicies) Validate(ctx context.Context, config contract.Config) AccessValidation {
	if _, err := accesscontrol.Prepare(config); err != nil {
		return AccessValidation{Errors: []string{err.Error()}}
	}
	tx, err := a.store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return AccessValidation{Errors: []string{"cannot validate policy references"}}
	}
	defer func() { _ = tx.Rollback() }()
	if err := accessReferences(ctx, tx, config); err != nil {
		return AccessValidation{Errors: []string{err.Error()}}
	}
	return AccessValidation{Valid: true, Errors: []string{}}
}

func accessReferences(ctx context.Context, tx *sql.Tx, config contract.Config) error {
	references := map[string][]string{}
	var visit func(contractroute.RuleExpr)
	visit = func(e contractroute.RuleExpr) {
		switch e.Type {
		case "user":
			references["user"] = append(references["user"], e.User.IDs...)
		case "group":
			references["group"] = append(references["group"], e.Group.IDs...)
		case "credential":
			references["credential"] = append(references["credential"], e.Credential.IDs...)
		case "all":
			for _, c := range e.All {
				visit(c)
			}
		case "any":
			for _, c := range e.Any {
				visit(c)
			}
		case "not":
			visit(*e.Not)
		}
	}
	for _, r := range config.Rules {
		for _, e := range r.Conditions {
			visit(e)
		}
	}
	// Fixed ordering and SQL statements; no identifiers supplied by a caller.
	for _, kind := range []string{"user", "group", "credential"} {
		ids := references[kind]
		slices.Sort(ids)
		ids = slices.Compact(ids)
		query := `SELECT count(*) FROM management_users WHERE id=?`
		if kind == "group" {
			query = `SELECT count(*) FROM traffic_groups WHERE id=? AND deleted=0`
		}
		if kind == "credential" {
			query = `SELECT count(*) FROM proxy_credentials WHERE id=?`
		}
		for _, id := range ids {
			var count int
			if err := tx.QueryRowContext(ctx, query, id).Scan(&count); err != nil {
				return errors.New("cannot validate policy references")
			}
			if count != 1 {
				return fmt.Errorf("unknown or deleted %s reference: %s", kind, id)
			}
		}
	}
	return nil
}

func (a *AccessPolicies) Save(ctx context.Context, actor Principal, config contract.Config) (contract.Config, error) {
	if !actor.Allows(TrafficAccessWrite) {
		return contract.Config{}, ErrForbidden
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	current := a.Controller.Config()
	if config.Revision != current.Revision || config.Revision >= 1<<53-1 {
		return contract.Config{}, ErrConflict
	}
	config.Revision++
	prepared, err := accesscontrol.Prepare(config)
	if err != nil {
		return contract.Config{}, fmt.Errorf("%w: %s", ErrInvalid, err)
	}
	tx, err := configchange.Begin(ctx, a.store.db, "access-policy")
	if err != nil {
		return contract.Config{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := accessReferences(ctx, tx, config); err != nil {
		return contract.Config{}, fmt.Errorf("%w: %s", ErrInvalid, err)
	}
	data, err := json.Marshal(config)
	if err != nil {
		return contract.Config{}, err
	}
	// The database revision protects against another process as well as stale UI.
	result, err := tx.ExecContext(ctx, `INSERT INTO traffic_access_config(id,revision,data) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,data=excluded.data WHERE traffic_access_config.revision=?`, config.Revision, string(data), current.Revision)
	if err != nil {
		return contract.Config{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return contract.Config{}, err
	}
	if changed != 1 {
		return contract.Config{}, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM traffic_access_groups`); err != nil {
		return contract.Config{}, err
	}
	groups := accessGroupIDs(config)
	for _, id := range groups {
		if _, err := tx.ExecContext(ctx, `INSERT INTO traffic_access_groups(group_id) VALUES(?)`, id); err != nil {
			return contract.Config{}, err
		}
	}
	info, _ := ctx.Value(auditKey{}).(auditInfo)
	changes, err := json.Marshal(struct{ Before, After contract.Config }{current, config})
	if err != nil {
		return contract.Config{}, err
	}
	info.changes = string(changes)
	info.policyRevision = strconv.FormatUint(config.Revision, 10)
	ctx = context.WithValue(ctx, auditKey{}, info)
	if err := recordEvent(ctx, tx, "traffic_access.updated", actor.UserID, "traffic-access"); err != nil {
		return contract.Config{}, err
	}
	if err := configchange.RecordValues(ctx, a.store.db, tx, "access-policy", "traffic-access", config.Revision, current, config, current, config); err != nil {
		return contract.Config{}, err
	}
	if err := configchange.Commit(ctx, tx); err != nil {
		return contract.Config{}, err
	}
	a.Controller.Activate(prepared)
	return a.Controller.Config(), nil
}

func accessGroupIDs(config contract.Config) []string {
	var ids []string
	var visit func(contractroute.RuleExpr)
	visit = func(e contractroute.RuleExpr) {
		switch e.Type {
		case "group":
			ids = append(ids, e.Group.IDs...)
		case "all":
			for _, c := range e.All {
				visit(c)
			}
		case "any":
			for _, c := range e.Any {
				visit(c)
			}
		case "not":
			visit(*e.Not)
		}
	}
	for _, r := range config.Rules {
		for _, e := range r.Conditions {
			visit(e)
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}
