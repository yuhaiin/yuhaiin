package auth

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"github.com/Asutorufa/yuhaiin/pkg/security/configchange"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
	"github.com/Asutorufa/yuhaiin/pkg/net/accesscontrol"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol/quota"
)

type ResourcePolicies struct {
	mu              sync.Mutex
	store           *Store
	proxy           *ProxyCredentials
	bindings        []trafficcontrol.IdentityBinding
	Control         *trafficcontrol.Controller
	Ledger          *quota.Ledger
	cancel          context.CancelFunc
	done            chan struct{}
	refreshFailures atomic.Uint64
	access          *accesscontrol.Controller
	pendingAlerts   []quota.Event
	alertBacklog    atomic.Int64
	alertFailures   atomic.Uint64
}

func NewResourcePolicies(ctx context.Context, store *Store, proxy *ProxyCredentials, access ...*accesscontrol.Controller) (_ *ResourcePolicies, err error) {
	if len(access) > 1 {
		return nil, ErrInvalid
	}
	ledger := quota.New(quotaStore{db: store.db})
	control := trafficcontrol.NewController()
	control.Manager = trafficcontrol.NewManagerWithQuotas(ledger)
	r := &ResourcePolicies{store: store, proxy: proxy, Control: control, Ledger: ledger, done: make(chan struct{})}
	if len(access) == 1 {
		r.access = access[0]
	}
	defer func() {
		if err != nil {
			control.Close()
			_ = ledger.Close(context.Background())
		}
	}()
	config := resource.Config{}
	var revision uint64
	var data string
	err = store.db.QueryRowContext(ctx, `SELECT revision,data FROM resource_config WHERE id=1`).Scan(&revision, &data)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		if err := json.Unmarshal([]byte(data), &config, json.RejectUnknownMembers(true)); err != nil {
			return nil, err
		}
		if config.Revision != revision {
			return nil, errors.New("resource policy revision is inconsistent")
		}
	}
	if err := control.ApplyResources(config, nil); err != nil {
		return nil, err
	}
	if err := proxy.SetResourceObserver(r.observeBindings); err != nil {
		return nil, err
	}
	workerCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	go func() {
		defer close(r.done)
		tick := time.NewTicker(time.Second)
		retire := time.NewTicker(time.Minute)
		defer tick.Stop()
		defer retire.Stop()
		for {
			select {
			case <-workerCtx.Done():
				return
			case <-ledger.Terminations():
				r.interruptQuotas()
			case <-retire.C:
				if err := r.retireQuotaState(workerCtx); err != nil {
					r.refreshFailures.Add(1)
				}
			case <-tick.C:
				r.mu.Lock()
				err := r.Control.RefreshQuotaWindows(workerCtx)
				r.mu.Unlock()
				if err != nil {
					r.refreshFailures.Add(1)
				}
				r.interruptQuotas()
				_ = r.flushQuotaAlerts(workerCtx)
			}
		}
	}()
	return r, nil
}

func (r *ResourcePolicies) interruptQuotas() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.access == nil || !r.Control.HasQuotaTermination() {
		return
	}
	decisions := make(map[[2]string]bool)
	r.access.InterruptWhere(func(subject netapi.TrafficSubject) bool {
		identity := subject.Identity
		if identity == nil || !identity.Valid() {
			return false
		}
		key := [2]string{identity.UserID, identity.CredentialID}
		if decision, exists := decisions[key]; exists {
			return decision
		}
		plan, err := r.Control.ResolveAuthenticated("", "", identity).QuotaPlan()
		decision := false
		if err == nil && plan != nil {
			effect, err := plan.Effects(time.Now())
			decision = err == nil && effect.Terminate
		}
		decisions[key] = decision
		return decision
	}, quota.ErrExhausted)
}

func (r *ResourcePolicies) observeBindings(bindings []trafficcontrol.IdentityBinding) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	prepared, err := r.Control.PrepareResources(context.Background(), r.Control.ResourceConfig(), bindings)
	if err != nil {
		return err
	}
	if err := r.Control.ActivateResources(prepared); err != nil {
		return err
	}
	r.bindings = bindings
	return nil
}

func (r *ResourcePolicies) Close() error {
	_ = r.proxy.SetResourceObserver(nil)
	r.cancel()
	<-r.done
	r.Control.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ledgerErr := r.Ledger.Close(ctx)
	for {
		if err := r.flushQuotaAlerts(ctx); err != nil {
			return errors.Join(ledgerErr, err)
		}
		if len(r.Ledger.Events()) == 0 {
			break
		}
	}
	return ledgerErr
}

func (r *ResourcePolicies) Validate(ctx context.Context, config resource.Config) AccessValidation {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.Control.PrepareResources(ctx, config, r.bindings); err != nil {
		return AccessValidation{Errors: []string{err.Error()}}
	}
	tx, err := r.store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return AccessValidation{Errors: []string{"cannot validate resource references"}}
	}
	defer func() { _ = tx.Rollback() }()
	if err := resourceReferences(ctx, tx, config); err != nil {
		return AccessValidation{Errors: []string{err.Error()}}
	}
	return AccessValidation{Valid: true, Errors: []string{}}
}

func (r *ResourcePolicies) Save(ctx context.Context, actor Principal, config resource.Config) (resource.Config, error) {
	if !actor.Allows(ResourceWrite) {
		return resource.Config{}, ErrForbidden
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	current := r.Control.ResourceConfig()
	if current.Revision != config.Revision || config.Revision >= 1<<53-1 {
		return resource.Config{}, ErrConflict
	}
	config.Revision++
	var prepared *trafficcontrol.PreparedResources
	var err error
	if configchange.Validating(ctx) {
		err = r.Control.ValidateResources(config, r.bindings)
	} else {
		prepared, err = r.Control.PrepareResources(ctx, config, r.bindings)
	}
	if err != nil {
		return resource.Config{}, fmt.Errorf("%w: %s", ErrInvalid, err)
	}
	tx, err := configchange.Begin(ctx, r.store.db, "resource-policy")
	if err != nil {
		return resource.Config{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := resourceReferences(ctx, tx, config); err != nil {
		return resource.Config{}, fmt.Errorf("%w: %s", ErrInvalid, err)
	}
	data, err := json.Marshal(config)
	if err != nil {
		return resource.Config{}, err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO resource_config(id,revision,data) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,data=excluded.data WHERE resource_config.revision=?`, config.Revision, string(data), current.Revision)
	if err != nil {
		return resource.Config{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return resource.Config{}, err
	}
	if n != 1 {
		return resource.Config{}, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM resource_groups`); err != nil {
		return resource.Config{}, err
	}
	for _, g := range config.Groups {
		if _, err := tx.ExecContext(ctx, `INSERT INTO resource_groups(group_id) VALUES(?)`, g.GroupID); err != nil {
			return resource.Config{}, err
		}
	}
	changes, err := json.Marshal(struct{ Before, After resource.Config }{current, config})
	if err != nil {
		return resource.Config{}, err
	}
	info, _ := ctx.Value(auditKey{}).(auditInfo)
	info.changes = string(changes)
	info.policyRevision = strconv.FormatUint(config.Revision, 10)
	if err := recordEvent(context.WithValue(ctx, auditKey{}, info), tx, "resource_policy.updated", actor.UserID, "resource-policy"); err != nil {
		return resource.Config{}, err
	}
	if err := configchange.RecordValues(ctx, r.store.db, tx, "resource-policy", "resource-policy", config.Revision, current, config, current, config); err != nil {
		return resource.Config{}, err
	}
	if err := configchange.Commit(ctx, tx); err != nil {
		return resource.Config{}, err
	}
	// This service owns all resource publications and holds its mutex across
	// persistence and activation; base QoS updates preserve the resource pointer.
	if err := r.Control.ActivateResources(prepared); err != nil {
		return resource.Config{}, err
	}
	return r.Control.ResourceConfig(), nil
}

func resourceReferences(ctx context.Context, tx *sql.Tx, config resource.Config) error {
	check := func(query, id string) error {
		var n int
		if err := tx.QueryRowContext(ctx, query, id).Scan(&n); err != nil {
			return errors.New("cannot validate resource references")
		}
		if n != 1 {
			return fmt.Errorf("unknown or deleted resource identity: %s", id)
		}
		return nil
	}
	for _, g := range config.Groups {
		if err := check(`SELECT count(*) FROM traffic_groups WHERE id=? AND deleted=0`, g.GroupID); err != nil {
			return err
		}
	}
	for _, u := range config.Users {
		if err := check(`SELECT count(*) FROM management_users WHERE id=?`, u.UserID); err != nil {
			return err
		}
	}
	for _, c := range config.Credentials {
		if err := check(`SELECT count(*) FROM proxy_credentials WHERE id=?`, c.CredentialID); err != nil {
			return err
		}
	}
	groups, users, credentials := map[string][]resource.Quota{}, map[string][]resource.Quota{}, map[string][]resource.Quota{}
	for _, g := range config.Groups {
		groups[g.GroupID] = g.Quotas
	}
	for _, u := range config.Users {
		users[u.UserID] = u.Policy.Quotas
	}
	for _, c := range config.Credentials {
		credentials[c.CredentialID] = c.Policy.Quotas
	}
	rows, err := tx.QueryContext(ctx, `SELECT scope,scope_id,quota_id,period FROM quota_definitions`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var scope, owner, id, period string
		if err := rows.Scan(&scope, &owner, &id, &period); err != nil {
			return err
		}
		var quotas []resource.Quota
		switch scope {
		case "group":
			quotas = groups[owner]
		case "credential":
			quotas = credentials[owner]
		case "user":
			var override bool
			quotas, override = users[owner]
			if !override {
				quotas = config.DefaultUser.Quotas
			}
		}
		for _, q := range quotas {
			if q.ID == id && q.Period != period {
				return errors.New("quota ID is already bound to a different UTC period; use a new ID")
			}
		}
	}
	return rows.Err()
}

func (r *ResourcePolicies) Status() resource.Status {
	d := r.Ledger.Diagnostics()
	return resource.Status{Revision: r.Control.ResourceConfig().Revision, Windows: d.Windows, PendingWrites: d.Pending, Denied: strconv.FormatUint(d.Denied, 10), PersistenceFailures: strconv.FormatUint(d.PersistenceFailures, 10), RefreshFailures: strconv.FormatUint(r.refreshFailures.Load(), 10), DroppedAlerts: strconv.FormatUint(d.DroppedEvents, 10), PendingAlerts: int(r.alertBacklog.Load()) + len(r.Ledger.Events()), AlertPersistenceFailures: strconv.FormatUint(r.alertFailures.Load(), 10)}
}
