package auth

import (
	"context"
	"database/sql"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/http"
	"slices"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/security/configchange"
)

type configurationChangeResponse struct {
	Store string `json:"store"`
	configchange.Change
	Activation string `json:"activation"`
}

func (c *ConfigurationChanges) response(ctx context.Context, store string, change configchange.Change) configurationChangeResponse {
	out := configurationChangeResponse{Store: store, Change: change, Activation: "staged"}
	if change.State != "committed" {
		return out
	}
	out.Activation = "superseded"
	if store == "configuration" {
		if c.configuration != nil {
			if status, err := c.configuration.Activation(ctx, change); err == nil {
				out.Activation = status
			} else {
				out.Activation = "unavailable"
			}
		}
		return out
	}
	if change.Kind == "group" {
		if c.server.Proxy == nil {
			out.Activation = "saved"
			return out
		}
		if strconv.FormatUint(c.server.Proxy.GroupRevision(change.ResourceID), 10) == change.Revision {
			out.Activation = "active"
		}
		return out
	}

	var revision uint64
	var err error
	switch change.Kind {
	case "access-policy":
		if c.server.Access == nil {
			out.Activation = "unavailable"
			return out
		}
		revision = c.server.Access.Controller.Config().Revision
	case "resource-policy":
		if c.server.Resources == nil {
			out.Activation = "unavailable"
			return out
		}
		revision = c.server.Resources.Control.ResourceConfig().Revision
	case "role":
		err = c.server.Store.db.QueryRowContext(ctx, `SELECT revision FROM management_roles WHERE id=?`, change.ResourceID).Scan(&revision)
	case "role-assignment":
		err = c.server.Store.db.QueryRowContext(ctx, `SELECT COALESCE((SELECT revision FROM management_role_assignments WHERE user_id=?),0)`, change.ResourceID).Scan(&revision)
	case "oidc-provider":
		err = c.server.Store.db.QueryRowContext(ctx, `SELECT revision FROM management_oauth_providers WHERE provider=?`, change.ResourceID).Scan(&revision)
	case "audit-settings":
		err = c.server.Store.db.QueryRowContext(ctx, `SELECT revision FROM management_audit_settings WHERE id=1`).Scan(&revision)
	default:
		out.Activation = "unavailable"
		return out
	}
	if errors.Is(err, sql.ErrNoRows) {
		out.Activation = "removed"
	} else if err != nil {
		out.Activation = "unavailable"
	} else if strconv.FormatUint(revision, 10) == change.Revision {
		out.Activation = "active"
	}
	return out
}
func (c *ConfigurationChanges) load(ctx context.Context, p Principal, store, id string, write bool) (*configchange.Journal, configchange.Change, error) {
	j, err := c.journal(store)
	if err != nil {
		return nil, configchange.Change{}, err
	}
	change, err := j.Get(ctx, id)
	if err != nil {
		return nil, change, err
	}
	if !allowedChangeKind(p, change.Kind, false) || write && (!p.Allows(ConfigurationWrite) || !allowedChangeKind(p, change.Kind, true)) {
		return nil, change, ErrForbidden
	}
	return j, change, nil
}
func (s *Server) registerConfigurationChanges(register func(string, Permission, http.HandlerFunc)) {
	c := s.Changes
	register("GET /api/v2/auth/changes/targets", ConfigurationRead, func(w http.ResponseWriter, r *http.Request) {
		p, _ := FromContext(r.Context())
		type target struct {
			Kind     string `json:"kind"`
			Store    string `json:"store"`
			Writable bool   `json:"writable"`
			Rollback bool   `json:"rollback"`
		}
		out := []target{}
		for kind := range configurationKinds {
			store := "identity"
			if kind == "route-rule" || kind == "route-list" || kind == "route-defaults" || kind == "route-order" {
				if c.configuration == nil {
					continue
				}
				store = "configuration"
			}
			if allowedChangeKind(p, kind, false) {
				out = append(out, target{kind, store, p.Allows(ConfigurationWrite) && allowedChangeKind(p, kind, true), p.Allows(ConfigurationWrite) && p.Allows(ConfigurationRollback) && allowedChangeKind(p, kind, true)})
			}
		}
		slices.SortFunc(out, func(a, b target) int {
			if a.Kind < b.Kind {
				return -1
			}
			if a.Kind > b.Kind {
				return 1
			}
			return 0
		})
		respond(w, out, nil)
	})
	register("GET /api/v2/auth/changes", ConfigurationRead, func(w http.ResponseWriter, r *http.Request) {
		p, _ := FromContext(r.Context())
		out := []configurationChangeResponse{}
		for _, store := range []string{"identity", "configuration"} {
			j, err := c.journal(store)
			if err != nil {
				continue
			}
			items, err := j.List(r.Context())
			if err != nil {
				respond(w, nil, err)
				return
			}
			for _, item := range items {
				if allowedChangeKind(p, item.Kind, false) && (r.URL.Query().Get("kind") == "" || r.URL.Query().Get("kind") == item.Kind) && (r.URL.Query().Get("state") == "" || r.URL.Query().Get("state") == item.State) {
					out = append(out, configurationChangeResponse{Store: store, Change: item})
				}
			}
		}
		slices.SortFunc(out, func(a, b configurationChangeResponse) int {
			if a.CreatedAt > b.CreatedAt {
				return -1
			}
			if a.CreatedAt < b.CreatedAt {
				return 1
			}
			return 0
		})
		respond(w, out, nil)
	})
	register("GET /api/v2/auth/changes/{store}/{id}", ConfigurationRead, func(w http.ResponseWriter, r *http.Request) {
		p, _ := FromContext(r.Context())
		_, item, err := c.load(r.Context(), p, r.PathValue("store"), r.PathValue("id"), false)
		if err != nil {
			respond(w, nil, err)
			return
		}
		respond(w, c.response(r.Context(), r.PathValue("store"), item), nil)
	})
	register("POST /api/v2/auth/changes", ConfigurationWrite, func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Store      string         `json:"store"`
			Kind       string         `json:"kind"`
			ResourceID string         `json:"resourceId"`
			Action     string         `json:"action"`
			Payload    jsontext.Value `json:"payload"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 2*configchange.MaxPayload+4096)
		if json.UnmarshalRead(r.Body, &in, json.RejectUnknownMembers(true)) != nil {
			authError(w, http.StatusBadRequest)
			return
		}
		p, _ := FromContext(r.Context())
		c.mu.Lock()
		defer c.mu.Unlock()
		out, err := c.stage(r.Context(), p, in.Store, in.Kind, in.ResourceID, in.Action, in.Payload)
		respond(w, configurationChangeResponse{Store: in.Store, Change: out, Activation: "staged"}, changeError(err))
	})
	register("POST /api/v2/auth/changes/{store}/{id}/validate", ConfigurationWrite, func(w http.ResponseWriter, r *http.Request) {
		p, _ := FromContext(r.Context())
		store, id := r.PathValue("store"), r.PathValue("id")
		c.mu.Lock()
		defer c.mu.Unlock()
		j, _, err := c.load(r.Context(), p, store, id, true)
		if err != nil {
			respond(w, nil, err)
			return
		}
		d, err := j.Payload(r.Context(), id)
		if err == nil {
			err = j.Validate(r.Context(), id, func(ctx context.Context) error { return c.applyDocument(ctx, p, store, d, false) })
		}
		respond(w, struct {
			Valid bool `json:"valid"`
		}{err == nil}, changeError(err))
	})
	register("POST /api/v2/auth/changes/{store}/{id}/commit", ConfigurationWrite, func(w http.ResponseWriter, r *http.Request) {
		p, _ := FromContext(r.Context())
		store, id := r.PathValue("store"), r.PathValue("id")
		c.mu.Lock()
		defer c.mu.Unlock()
		j, _, err := c.load(r.Context(), p, store, id, true)
		if err != nil {
			respond(w, nil, err)
			return
		}
		d, err := j.Payload(r.Context(), id)
		if err != nil {
			respond(w, nil, err)
			return
		}
		out, err := j.Commit(r.Context(), id, func(ctx context.Context) error { return c.applyDocument(ctx, p, store, d, false) })
		respond(w, c.response(r.Context(), store, out), changeError(err))
	})
	register("POST /api/v2/auth/changes/{store}/{id}/rollback", ConfigurationRollback, func(w http.ResponseWriter, r *http.Request) {
		p, _ := FromContext(r.Context())
		store, id := r.PathValue("store"), r.PathValue("id")
		c.mu.Lock()
		defer c.mu.Unlock()
		j, entry, err := c.load(r.Context(), p, store, id, true)
		if err != nil {
			respond(w, nil, err)
			return
		}
		if entry.State != "committed" {
			respond(w, nil, ErrConflict)
			return
		}
		d, err := j.Payload(r.Context(), id)
		if err != nil {
			respond(w, nil, err)
			return
		}
		out, err := j.Stage(r.Context(), d.Kind, d.ResourceID, id, func(ctx context.Context) error { return c.applyDocument(ctx, p, store, d, true) })
		respond(w, configurationChangeResponse{Store: store, Change: out, Activation: "staged"}, changeError(err))
	})
	register("DELETE /api/v2/auth/changes/{store}/{id}", ConfigurationWrite, func(w http.ResponseWriter, r *http.Request) {
		p, _ := FromContext(r.Context())
		c.mu.Lock()
		defer c.mu.Unlock()
		j, _, err := c.load(r.Context(), p, r.PathValue("store"), r.PathValue("id"), true)
		if err == nil {
			err = j.Discard(r.Context(), r.PathValue("id"))
		}
		respond(w, struct{}{}, changeError(err))
	})
}
