package auth

import (
	"context"
	"database/sql"
	"encoding/json/jsontext"
	"errors"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/security/configchange"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
)

type ConfigurationChanges struct {
	server        *Server
	identity      *configchange.Journal
	configuration configchange.Backend
	mu            sync.Mutex
}

type changeKind struct {
	read, write []Permission
	session     bool
}

var configurationKinds = map[string]changeKind{
	"group":           {read: []Permission{UsersManage}, write: []Permission{UsersManage}},
	"role":            {read: []Permission{RolesRead}, write: []Permission{RolesWrite}},
	"role-assignment": {read: []Permission{RolesRead}, write: []Permission{RolesWrite, UsersManage}},
	"access-policy":   {read: []Permission{TrafficAccessRead}, write: []Permission{TrafficAccessWrite}},
	"resource-policy": {read: []Permission{ResourceRead}, write: []Permission{ResourceWrite}},
	"oidc-provider":   {read: []Permission{SecurityRead}, write: []Permission{SecurityWrite}, session: true},
	"audit-settings":  {read: []Permission{SecurityRead}, write: []Permission{SecurityWrite}},
	"route-rule":      {read: []Permission{RoutesRead}, write: []Permission{RoutesWrite}},
	"route-defaults":  {read: []Permission{RoutesRead}, write: []Permission{RoutesWrite}},
	"route-order":     {read: []Permission{RoutesRead}, write: []Permission{RoutesWrite}},
	"route-list":      {read: []Permission{RoutesRead}, write: []Permission{RoutesWrite}},
}

func allowedChangeKind(p Principal, kind string, write bool) bool {
	policy, ok := configurationKinds[kind]
	if !ok || policy.session && p.CredentialType != "session" {
		return false
	}
	required := policy.read
	if write {
		required = policy.write
	}
	for _, permission := range required {
		if !p.Allows(permission) {
			return false
		}
	}
	return true
}
func (c *ConfigurationChanges) actorContext(ctx context.Context, p Principal) context.Context {
	return configchange.WithActor(ctx, configchange.Actor{ID: p.UserID, Authorize: func(ctx context.Context, db *sql.DB, tx *sql.Tx, kind string) error {
		authorize := func(identityTX *sql.Tx) error {
			current, err := freshRoleActor(ctx, identityTX, p)
			if err != nil {
				return err
			}
			if !allowedChangeKind(current, kind, true) || configchange.Workflow(ctx) && (!current.Allows(ConfigurationRead) || !current.Allows(ConfigurationWrite) || !allowedChangeKind(current, kind, false)) || configchange.RollbackOf(ctx) != "" && !current.Allows(ConfigurationRollback) {
				return ErrForbidden
			}
			return nil
		}
		if db == c.server.Store.db {
			return authorize(tx)
		}
		if configchange.Workflow(ctx) && (c.configuration == nil || db != c.configuration.Journal().Database()) || kind != "route-rule" && kind != "route-defaults" && kind != "route-list" && kind != "route-order" {
			return ErrForbidden
		}
		privateTX, err := c.server.Store.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = privateTX.Rollback() }()
		if err = authorize(privateTX); err != nil {
			return err
		}
		if !configchange.Validating(ctx) && !configchange.CheckingOnly(ctx) {
			if err = recordEvent(ctx, privateTX, "configuration.change_authorized", p.UserID, kind); err != nil {
				return err
			}
		}
		return privateTX.Commit()
	}})
}
func (c *ConfigurationChanges) journal(store string) (*configchange.Journal, error) {
	if store == "identity" {
		return c.identity, nil
	}
	if store == "configuration" && c.configuration != nil {
		return c.configuration.Journal(), nil
	}
	return nil, ErrInvalid
}
func changeError(err error) error {
	switch {
	case errors.Is(err, configchange.ErrConflict), errors.Is(err, configchange.ErrLimit):
		return ErrConflict
	case errors.Is(err, secret.ErrManage), errors.Is(err, secret.ErrSecurity), errors.Is(err, secret.ErrExecute), errors.Is(err, secret.ErrAuthorization):
		return ErrForbidden
	case errors.Is(err, secret.ErrPreserved):
		return ErrConflict
	case errors.Is(err, configchange.ErrInvalid):
		return ErrInvalid
	default:
		return err
	}
}
func (c *ConfigurationChanges) applyDocument(ctx context.Context, p Principal, store string, d configchange.Document, rollback bool) error {
	if !allowedChangeKind(p, d.Kind, true) {
		return ErrForbidden
	}
	if store == "configuration" {
		if c.configuration == nil {
			return ErrInvalid
		}
		return c.configuration.Apply(ctx, d, rollback)
	}
	if store != "identity" {
		return ErrInvalid
	}
	return c.applyIdentityDocument(ctx, p, d, rollback)
}
func (c *ConfigurationChanges) stage(ctx context.Context, p Principal, store, kind, id, action string, payload jsontext.Value) (configchange.Change, error) {
	if !p.Allows(ConfigurationRead) || !p.Allows(ConfigurationWrite) || !allowedChangeKind(p, kind, false) || !allowedChangeKind(p, kind, true) {
		return configchange.Change{}, ErrForbidden
	}
	if store == "configuration" {
		if c.configuration == nil {
			return configchange.Change{}, ErrInvalid
		}
		return c.configuration.Stage(ctx, kind, id, action, payload)
	}
	if store != "identity" {
		return configchange.Change{}, ErrInvalid
	}
	return c.stageIdentity(ctx, p, kind, id, action, payload)
}
