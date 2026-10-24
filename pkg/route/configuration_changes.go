package route

import (
	"context"
	"database/sql"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"strconv"
	"uuid"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/security/configchange"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

type ConfigurationChanges struct {
	db       *sql.DB
	journal  *configchange.Journal
	runtime  ConfigurationRuntime
	editor   *plainstore.RouteEditorStore
	rules    *plainstore.RouteRuleStore
	lists    *plainstore.RouteListStore
	settings *plainstore.RouteSettingsStore
}

func NewConfigurationChanges(db *sql.DB, runtime ConfigurationRuntime) *ConfigurationChanges {
	return &ConfigurationChanges{db: db, journal: configchange.New(db), runtime: runtime, editor: plainstore.NewRouteEditorStore(db), rules: plainstore.NewRouteRuleStore(db), lists: plainstore.NewRouteListStore(db), settings: plainstore.NewRouteSettingsStore(db)}
}
func (c *ConfigurationChanges) Journal() *configchange.Journal { return c.journal }
func (c *ConfigurationChanges) Enable(ctx context.Context) error {
	if c.runtime == nil {
		return errors.New("configuration runtime is unavailable")
	}
	var count int
	if err := c.db.QueryRowContext(ctx, `SELECT count(*) FROM configuration_changes`).Scan(&count); err != nil {
		return err
	}
	_, err := c.db.ExecContext(ctx, `PRAGMA synchronous=FULL`)
	return err
}
func decodeConfiguration(value jsontext.Value, out any) error {
	if len(value) == 0 || string(value) == "null" || len(value) > configchange.MaxPayload || json.Unmarshal(value, out, json.RejectUnknownMembers(true)) != nil {
		return configchange.ErrInvalid
	}
	return nil
}
func nullConfiguration(value jsontext.Value) bool { return len(value) == 0 || string(value) == "null" }
func configurationError(err error) error {
	if errors.Is(err, plainstore.ErrConflict) {
		return configchange.ErrConflict
	}
	if errors.Is(err, plainstore.ErrNotFound) {
		return sql.ErrNoRows
	}
	if _, ok := errors.AsType[*plainstore.ResourceInUseError](err); ok {
		return configchange.ErrConflict
	}
	return err
}
func (c *ConfigurationChanges) perform(ctx context.Context, kind string, prepare func(context.Context) ([]string, error), apply func(context.Context) error) error {
	return configurationError(c.runtime.WithConfiguration(ctx, func(ctx context.Context) error {
		if err := configchange.Check(ctx, c.db, kind); err != nil {
			return err
		}
		urls, err := prepare(ctx)
		if err != nil {
			return err
		}
		if err = c.runtime.PrefetchConfiguration(ctx, urls); err != nil {
			return err
		}
		ctx = configchange.WithCommitter(ctx, c.runtime.CommitConfiguration)
		return apply(ctx)
	}))
}
func (c *ConfigurationChanges) ruleURLs(ctx context.Context, draft contractroute.RuleDraft) ([]string, error) {
	owned := map[string]bool{}
	for _, v := range draft.Lists {
		owned[v.ID] = true
	}
	urls := []string{}
	err := contractroute.VisitListRefs(draft.Rule.Rules, func(_ string, id string) error {
		if owned[id] {
			return nil
		}
		v, err := c.lists.GetRouteList(ctx, id)
		if err != nil {
			return err
		}
		if v.Source.Remote != nil {
			urls = append(urls, v.Source.Remote.URLs...)
		}
		return nil
	})
	return urls, err
}
func (c *ConfigurationChanges) Stage(ctx context.Context, kind, id, action string, payload jsontext.Value) (configchange.Change, error) {
	if kind != "route-rule" && kind != "route-defaults" && kind != "route-list" && kind != "route-order" {
		return configchange.Change{}, configchange.ErrInvalid
	}
	planned := id
	if planned == "" {
		planned = uuid.New().String()
	}
	return c.journal.Stage(ctx, kind, planned, "", func(ctx context.Context) error {
		if action == "delete" {
			var v struct {
				Revision uint64 `json:"revision"`
			}
			if err := decodeConfiguration(payload, &v); err != nil {
				return err
			}
			return c.perform(ctx, kind, func(context.Context) ([]string, error) { return nil, nil }, func(ctx context.Context) error {
				switch kind {
				case "route-rule":
					current, err := c.rules.RuleChange(ctx, id)
					if err != nil {
						return err
					}
					if current.Draft.Rule.Revision != v.Revision {
						return configchange.ErrConflict
					}
					return c.rules.DeleteRule(ctx, id)
				case "route-list":
					current, err := c.lists.GetRouteList(ctx, id)
					if err != nil {
						return err
					}
					if current.Revision != v.Revision {
						return configchange.ErrConflict
					}
					return c.lists.DeleteRouteList(ctx, id)
				default:
					return configchange.ErrInvalid
				}
			})
		}
		if action != "" && action != "save" {
			return configchange.ErrInvalid
		}
		switch kind {
		case "route-rule":
			var v contractroute.RuleDraft
			if err := decodeConfiguration(payload, &v); err != nil {
				return err
			}
			if len(v.ShareLists) > 0 {
				return configchange.ErrInvalid
			}
			if id != "" && v.Rule.ID != id {
				return configchange.ErrInvalid
			}
			if v.Rule.ID == "" {
				v.Rule.ID = configchange.NewResourceID(ctx, planned)
			}
			return c.perform(ctx, kind, func(ctx context.Context) ([]string, error) { return c.ruleURLs(ctx, v) }, func(ctx context.Context) error { _, err := c.editor.Save(ctx, v); return err })
		case "route-order":
			var v struct {
				IDs    []string `json:"ids"`
				Source struct {
					ID string `json:"id"`
				} `json:"source"`
				Target struct {
					ID string `json:"id"`
				} `json:"target"`
				Operate string `json:"operate"`
			}
			if err := decodeConfiguration(payload, &v); err != nil {
				return err
			}
			return c.perform(ctx, kind, func(context.Context) ([]string, error) { return nil, nil }, func(ctx context.Context) error {
				if v.IDs != nil {
					return c.rules.SaveOrder(ctx, v.IDs)
				}
				return c.rules.ChangePriority(ctx, v.Source.ID, v.Target.ID, v.Operate)
			})
		case "route-defaults":
			var v contractroute.Config
			if err := decodeConfiguration(payload, &v); err != nil {
				return err
			}
			return c.perform(ctx, kind, func(context.Context) ([]string, error) { return nil, nil }, func(ctx context.Context) error { _, err := c.settings.SaveConfig(ctx, v); return err })
		case "route-list":
			var v contractroute.RouteListDetail
			if err := decodeConfiguration(payload, &v); err != nil {
				return err
			}
			if id != "" && v.ID != id {
				return configchange.ErrInvalid
			}
			if v.ID == "" {
				v.ID = configchange.NewResourceID(ctx, planned)
			}
			var resolved contractroute.RouteListDetail
			return c.perform(ctx, kind, func(ctx context.Context) ([]string, error) {
				before, err := c.lists.GetRouteList(ctx, v.ID)
				if err != nil && !errors.Is(err, plainstore.ErrNotFound) && !errors.Is(err, sql.ErrNoRows) {
					return nil, err
				}
				resolved, err = secret.Merge(ctx, v, before)
				if err != nil {
					return nil, err
				}
				if resolved.Source.Remote != nil {
					return resolved.Source.Remote.URLs, nil
				}
				return nil, nil
			}, func(ctx context.Context) error {
				return c.lists.SaveRouteList(secret.WithResolvedConfiguration(ctx), resolved, 0)
			})
		default:
			return configchange.ErrInvalid
		}
	})
}
func (c *ConfigurationChanges) current(ctx context.Context, kind, id string) (jsontext.Value, error) {
	var value any
	var err error
	switch kind {
	case "route-order":
		value, err = c.rules.Order(ctx)
	case "route-rule":
		value, err = c.rules.RuleChange(ctx, id)
	case "route-defaults":
		value, err = c.settings.Settings(ctx)
	case "route-list":
		var v contractroute.RouteListDetail
		v, err = c.lists.GetRouteList(ctx, id)
		v.ErrorMsgs = nil
		value = v
	default:
		return nil, configchange.ErrInvalid
	}
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, plainstore.ErrNotFound) {
		return jsontext.Value("null"), nil
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(value, json.Deterministic(true))
}
func (c *ConfigurationChanges) Apply(ctx context.Context, d configchange.Document, rollback bool) error {
	before, after := d.Before, d.After
	if rollback {
		after = d.Before
		var err error
		before, err = c.current(ctx, d.Kind, d.ResourceID)
		if err != nil {
			return err
		}
	}
	switch d.Kind {
	case "route-order":
		var entries []plainstore.RouteOrderEntry
		if err := decodeConfiguration(after, &entries); err != nil {
			return err
		}
		ids := make([]string, 0, len(entries))
		for _, entry := range entries {
			ids = append(ids, entry.ID)
		}
		return c.perform(ctx, d.Kind, func(context.Context) ([]string, error) { return nil, nil }, func(ctx context.Context) error { return c.rules.SaveOrder(ctx, ids) })
	case "route-rule":
		var base, desired plainstore.RouteRuleChange
		if !nullConfiguration(before) {
			if err := decodeConfiguration(before, &base); err != nil {
				return err
			}
		}
		if nullConfiguration(after) {
			if nullConfiguration(before) {
				return configchange.ErrConflict
			}
			return c.perform(ctx, d.Kind, func(context.Context) ([]string, error) { return nil, nil }, func(ctx context.Context) error { return c.rules.DeleteRule(ctx, d.ResourceID) })
		}
		if err := decodeConfiguration(after, &desired); err != nil {
			return err
		}
		desired.Draft.Rule.ID = d.ResourceID
		desired.Draft.Rule.Revision = base.Draft.Rule.Revision
		return c.perform(ctx, d.Kind, func(ctx context.Context) ([]string, error) { return c.ruleURLs(ctx, desired.Draft) }, func(ctx context.Context) error {
			_, err := c.editor.Save(plainstore.WithRulePosition(ctx, desired.Priority), desired.Draft)
			return err
		})
	case "route-defaults":
		if nullConfiguration(before) || nullConfiguration(after) {
			return configchange.ErrInvalid
		}
		var base, desired plainstore.RouteSettings
		if err := decodeConfiguration(before, &base); err != nil {
			return err
		}
		if err := decodeConfiguration(after, &desired); err != nil {
			return err
		}
		config := routeConfigFromStore(desired)
		v := contractroute.Config{Revision: base.Revision, DefaultMode: config.DefaultMode, DefaultTarget: config.DefaultTarget, DirectResolver: config.DirectResolver, ProxyResolver: config.ProxyResolver, ResolveLocally: config.ResolveLocally}
		switch desired.UDPProxyFQDN {
		case 1:
			v.UdpProxyFqdnStrategy = "resolve"
		case 2:
			v.UdpProxyFqdnStrategy = "skip_resolve"
		}
		return c.perform(ctx, d.Kind, func(context.Context) ([]string, error) { return nil, nil }, func(ctx context.Context) error { _, err := c.settings.SaveConfig(ctx, v); return err })
	case "route-list":
		var base, desired contractroute.RouteListDetail
		if !nullConfiguration(before) {
			if err := decodeConfiguration(before, &base); err != nil {
				return err
			}
		}
		if nullConfiguration(after) {
			if nullConfiguration(before) {
				return configchange.ErrConflict
			}
			return c.perform(ctx, d.Kind, func(context.Context) ([]string, error) { return nil, nil }, func(ctx context.Context) error { return c.lists.DeleteRouteList(ctx, d.ResourceID) })
		}
		if err := decodeConfiguration(after, &desired); err != nil {
			return err
		}
		desired.ID = d.ResourceID
		desired.Revision = base.Revision
		var resolved contractroute.RouteListDetail
		return c.perform(ctx, d.Kind, func(ctx context.Context) ([]string, error) {
			current, err := c.lists.GetRouteList(ctx, d.ResourceID)
			if err != nil && !errors.Is(err, plainstore.ErrNotFound) && !errors.Is(err, sql.ErrNoRows) {
				return nil, err
			}
			if current.Revision != base.Revision {
				return nil, configchange.ErrConflict
			}
			resolved, err = secret.Merge(secret.WithResolvedConfiguration(ctx), desired, current)
			if err != nil {
				return nil, err
			}
			if resolved.Source.Remote != nil {
				return resolved.Source.Remote.URLs, nil
			}
			return nil, nil
		}, func(ctx context.Context) error {
			return c.lists.SaveRouteList(secret.WithResolvedConfiguration(ctx), resolved, 0)
		})
	default:
		return configchange.ErrInvalid
	}
}
func (c *ConfigurationChanges) Activation(ctx context.Context, change configchange.Change) (string, error) {
	status, err := c.runtime.ActivationStatus(ctx)
	if err != nil {
		return "unavailable", err
	}
	if status.SavedRevision != status.AppliedRevision {
		return "pending", nil
	}
	raw, err := c.current(ctx, change.Kind, change.ResourceID)
	if err != nil {
		return "unavailable", err
	}
	if nullConfiguration(raw) {
		return "removed", nil
	}
	var revision uint64
	switch change.Kind {
	case "route-order":
		revision = status.SavedRevision
	case "route-rule":
		var v plainstore.RouteRuleChange
		if err = json.Unmarshal(raw, &v); err != nil {
			return "unavailable", err
		}
		revision = v.Draft.Rule.Revision
	case "route-list":
		var v contractroute.RouteListDetail
		if err = json.Unmarshal(raw, &v); err != nil {
			return "unavailable", err
		}
		revision = v.Revision
	case "route-defaults":
		var v plainstore.RouteSettings
		if err = json.Unmarshal(raw, &v); err != nil {
			return "unavailable", err
		}
		revision = v.Revision
	}
	if strconv.FormatUint(revision, 10) == change.Revision {
		return "active", nil
	}
	return "superseded", nil
}

var _ configchange.Backend = (*ConfigurationChanges)(nil)
