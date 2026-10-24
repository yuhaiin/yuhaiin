package auth

import (
	"context"
	"database/sql"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"uuid"

	access "github.com/Asutorufa/yuhaiin/pkg/contract/access"
	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
	"github.com/Asutorufa/yuhaiin/pkg/security/configchange"
)

func decodeChange(value jsontext.Value, out any) error {
	if isNull(value) || len(value) > configchange.MaxPayload || json.Unmarshal(value, out, json.RejectUnknownMembers(true)) != nil {
		return ErrInvalid
	}
	return nil
}
func (c *ConfigurationChanges) stageIdentity(ctx context.Context, p Principal, kind, id, action string, payload jsontext.Value) (configchange.Change, error) {
	planned := id
	if planned == "" {
		planned = uuid.New().String()
	}
	return c.identity.Stage(ctx, kind, planned, "", func(ctx context.Context) error {
		if action == "delete" {
			var request struct {
				Revision uint64 `json:"revision"`
			}
			if err := decodeChange(payload, &request); err != nil {
				return err
			}
			switch kind {
			case "group":
				return c.mutateGroup(ctx, p, id, GroupRequest{Revision: request.Revision}, true)
			case "role":
				return c.server.Store.DeleteRole(ctx, p, id, request.Revision)
			case "oidc-provider":
				current, err := c.server.Store.oauthProvider(ctx, id)
				if err != nil {
					return err
				}
				if current.Revision != request.Revision {
					return ErrConflict
				}
				return c.mutateProvider(ctx, p, OAuthProvider{Provider: id}, true)
			default:
				return ErrInvalid
			}
		}
		if action != "" && action != "save" {
			return ErrInvalid
		}
		switch kind {
		case "group":
			var v GroupRequest
			if err := decodeChange(payload, &v); err != nil {
				return err
			}
			return c.mutateGroup(ctx, p, id, v, false)
		case "role":
			var v Role
			if err := decodeChange(payload, &v); err != nil {
				return err
			}
			if v.ID != id {
				return ErrInvalid
			}
			_, err := c.server.Store.SaveRole(ctx, p, v)
			return err
		case "role-assignment":
			var v struct {
				Revision uint64   `json:"revision"`
				RoleIDs  []string `json:"roleIds"`
			}
			if err := decodeChange(payload, &v); err != nil {
				return err
			}
			_, err := c.server.Store.AssignRoles(ctx, p, id, v.Revision, v.RoleIDs)
			return err
		case "access-policy":
			if c.server.Access == nil {
				return ErrInvalid
			}
			var v access.Config
			if err := decodeChange(payload, &v); err != nil {
				return err
			}
			_, err := c.server.Access.Save(ctx, p, v)
			return err
		case "resource-policy":
			if c.server.Resources == nil {
				return ErrInvalid
			}
			var v resource.Config
			if err := decodeChange(payload, &v); err != nil {
				return err
			}
			_, err := c.server.Resources.Save(ctx, p, v)
			return err
		case "oidc-provider":
			var v OAuthProvider
			if err := decodeChange(payload, &v); err != nil {
				return err
			}
			if v.Provider != id {
				return ErrInvalid
			}
			return c.mutateProvider(ctx, p, v, false)
		case "audit-settings":
			var v AuditSettingsRequest
			if err := decodeChange(payload, &v); err != nil {
				return err
			}
			_, err := c.server.Store.SaveAuditSettings(ctx, p, v)
			return err
		default:
			return ErrInvalid
		}
	})
}
func (c *ConfigurationChanges) mutateGroup(ctx context.Context, p Principal, id string, v GroupRequest, remove bool) error {
	var err error
	if remove {
		err = c.server.Store.DeleteGroup(ctx, p, id, v.Revision)
	} else {
		_, err = c.server.Store.SaveGroup(ctx, p, id, v)
	}
	if err == nil && c.server.Proxy != nil {
		err = c.server.Proxy.Reload()
	}
	return err
}
func (c *ConfigurationChanges) mutateProvider(ctx context.Context, p Principal, v OAuthProvider, remove bool) error {
	var err error
	if remove {
		err = c.server.Store.DeleteOAuthProvider(ctx, p.UserID, v.Provider)
	} else {
		err = c.server.Store.SaveOAuthProvider(ctx, p.UserID, v)
	}
	if err == nil && c.server.OAuth != nil {
		c.server.OAuth.invalidate(v.Provider)
	}
	return err
}
func (c *ConfigurationChanges) currentIdentity(ctx context.Context, p Principal, kind, id string) (jsontext.Value, error) {
	var value any
	var err error
	switch kind {
	case "group":
		var v Group
		v, err = c.server.Store.Group(ctx, id)
		value = v
	case "role":
		tx, e := c.server.Store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if e != nil {
			return nil, e
		}
		defer func() { _ = tx.Rollback() }()
		value, err = loadRole(ctx, tx, id)
	case "role-assignment":
		value, err = c.server.Store.RoleAssignment(ctx, p, id)
	case "access-policy":
		if c.server.Access == nil {
			return nil, ErrInvalid
		}
		value = c.server.Access.Controller.Config()
	case "resource-policy":
		if c.server.Resources == nil {
			return nil, ErrInvalid
		}
		value = c.server.Resources.Control.ResourceConfig()
	case "oidc-provider":
		value, err = c.server.Store.oauthProvider(ctx, id)
	case "audit-settings":
		var cfg auditConfiguration
		cfg, err = readAuditConfiguration(ctx, c.server.Store.db)
		value = AuditSettingsRequest{AuditSettings: cfg.AuditSettings, Token: cfg.token}
	default:
		return nil, ErrInvalid
	}
	if errors.Is(err, sql.ErrNoRows) {
		return jsontext.Value("null"), nil
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(value, json.Deterministic(true))
}
func isNull(value jsontext.Value) bool { return len(value) == 0 || string(value) == "null" }

// Documents are loaded only from the private journal. Rebase a rollback onto
// current revisions and run the original authorization/reference checks again.
// It restores policy, never session rows, credential generations or bindings.
func (c *ConfigurationChanges) applyIdentityDocument(ctx context.Context, p Principal, d configchange.Document, rollback bool) error {
	before, after := d.Before, d.After
	if rollback {
		after = d.Before
		var err error
		before, err = c.currentIdentity(ctx, p, d.Kind, d.ResourceID)
		if err != nil {
			return err
		}
	}
	switch d.Kind {
	case "group":
		var base, desired Group
		if !isNull(before) {
			if err := decodeChange(before, &base); err != nil {
				return err
			}
		}
		if isNull(after) {
			if isNull(before) {
				return ErrConflict
			}
			return c.mutateGroup(ctx, p, d.ResourceID, GroupRequest{Revision: base.Revision}, true)
		}
		if err := decodeChange(after, &desired); err != nil {
			return err
		}
		if desired.Deleted {
			return c.mutateGroup(ctx, p, d.ResourceID, GroupRequest{Revision: base.Revision}, true)
		}
		id := d.ResourceID
		if isNull(before) {
			id = ""
		}
		if base.Deleted {
			ctx = configchange.WithRestoration(ctx)
		}
		return c.mutateGroup(ctx, p, id, GroupRequest{Name: desired.Name, Description: desired.Description, Members: desired.Members, Revision: base.Revision}, false)
	case "role":
		var base, desired Role
		if !isNull(before) {
			if err := decodeChange(before, &base); err != nil {
				return err
			}
		}
		if isNull(after) {
			if isNull(before) {
				return ErrConflict
			}
			return c.server.Store.DeleteRole(ctx, p, d.ResourceID, base.Revision)
		}
		if err := decodeChange(after, &desired); err != nil {
			return err
		}
		desired.Revision = base.Revision
		desired.ID = d.ResourceID
		if isNull(before) {
			desired.ID = ""
		}
		_, err := c.server.Store.SaveRole(ctx, p, desired)
		return err
	case "role-assignment":
		if isNull(before) || isNull(after) {
			return ErrInvalid
		}
		var base, desired RoleAssignment
		if err := decodeChange(before, &base); err != nil {
			return err
		}
		if err := decodeChange(after, &desired); err != nil {
			return err
		}
		_, err := c.server.Store.AssignRoles(ctx, p, d.ResourceID, base.Revision, desired.RoleIDs)
		return err
	case "access-policy":
		if c.server.Access == nil || isNull(after) {
			return ErrInvalid
		}
		var base, desired access.Config
		if err := decodeChange(before, &base); err != nil {
			return err
		}
		if err := decodeChange(after, &desired); err != nil {
			return err
		}
		desired.Revision = base.Revision
		_, err := c.server.Access.Save(ctx, p, desired)
		return err
	case "resource-policy":
		if c.server.Resources == nil || isNull(after) {
			return ErrInvalid
		}
		var base, desired resource.Config
		if err := decodeChange(before, &base); err != nil {
			return err
		}
		if err := decodeChange(after, &desired); err != nil {
			return err
		}
		desired.Revision = base.Revision
		_, err := c.server.Resources.Save(ctx, p, desired)
		return err
	case "oidc-provider":
		var base, desired OAuthProvider
		if !isNull(before) {
			if err := decodeChange(before, &base); err != nil {
				return err
			}
		}
		if isNull(after) {
			if isNull(before) {
				return ErrConflict
			}
			return c.mutateProvider(ctx, p, OAuthProvider{Provider: d.ResourceID}, true)
		}
		if err := decodeChange(after, &desired); err != nil {
			return err
		}
		desired.Provider = d.ResourceID
		desired.Revision = base.Revision
		desired.ClearSecret = false
		switch desired.ClientSecret {
		case base.ClientSecret:
			desired.ClientSecret = ""
		case "":
			desired.ClearSecret = true
		}
		return c.mutateProvider(ctx, p, desired, false)
	case "audit-settings":
		if isNull(before) || isNull(after) {
			return ErrInvalid
		}
		var base, desired AuditSettingsRequest
		if err := decodeChange(before, &base); err != nil {
			return err
		}
		if err := decodeChange(after, &desired); err != nil {
			return err
		}
		desired.Revision = base.Revision
		desired.ClearEndpoint = false
		desired.ClearToken = false
		switch desired.Endpoint {
		case base.Endpoint:
			desired.Endpoint = ""
		case "":
			desired.ClearEndpoint = true
		}
		switch desired.Token {
		case base.Token:
			desired.Token = ""
		case "":
			desired.ClearToken = true
		}
		_, err := c.server.Store.SaveAuditSettings(ctx, p, desired)
		return err
	default:
		return ErrInvalid
	}
}
