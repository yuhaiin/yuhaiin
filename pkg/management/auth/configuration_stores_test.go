package auth

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	routecore "github.com/Asutorufa/yuhaiin/pkg/route"
	"github.com/Asutorufa/yuhaiin/pkg/security/configchange"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

// Routing candidate compilation/publication is covered by the core runtime
// integration tests. This boundary fixture isolates the private audit authority
// and real configuration-store transactions without opening proxy listeners.
type configurationBoundaryRuntime struct{}

func (configurationBoundaryRuntime) WithConfiguration(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}
func (configurationBoundaryRuntime) PrefetchConfiguration(context.Context, []string) error {
	return nil
}
func (configurationBoundaryRuntime) CommitConfiguration(_ context.Context, tx *sql.Tx, validate bool) error {
	if validate {
		return configchange.ErrValidation
	}
	return tx.Commit()
}
func (configurationBoundaryRuntime) ActivationStatus(context.Context) (contractroute.RuleActivationStatus, error) {
	return contractroute.RuleActivationStatus{}, nil
}

func TestConfigurationSeparateStoresRequireDurablePrivateAuthorization(t *testing.T) {
	f := configurationTestServer(t)
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "configuration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	backend := routecore.NewConfigurationChanges(db.DB(), configurationBoundaryRuntime{})
	if err = backend.Enable(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.server.Changes.configuration = backend
	current, err := plainstore.NewRouteSettingsStore(db.DB()).Settings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	payload := contractroute.Config{Revision: current.Revision, DefaultMode: "direct"}
	request := map[string]any{"store": "configuration", "kind": "route-defaults", "payload": payload}
	staged := parseConfigurationResponse(t, f.request(t, "POST", "/changes", f.proof, request, 200))
	if staged.Store != "configuration" {
		t.Fatal("wrong store")
	}
	// There must be no cross-store payload copy, even for an administrator.
	f.request(t, "GET", "/changes/identity/"+staged.ID, f.proof, nil, 404)
	targetPath := "/changes/configuration/" + staged.ID + "/commit"
	if _, err = f.s.db.ExecContext(t.Context(), `CREATE TRIGGER block_private_intent BEFORE INSERT ON management_security_events WHEN NEW.event='configuration.change_authorized' BEGIN SELECT RAISE(FAIL,'audit unavailable');END`); err != nil {
		t.Fatal(err)
	}
	f.request(t, "POST", targetPath, f.proof, struct{}{}, 500)
	saved, err := plainstore.NewRouteSettingsStore(db.DB()).Settings(t.Context())
	if err != nil || saved.Revision != current.Revision {
		t.Fatal("configuration changed without private authorization", err)
	}
	if _, err = f.s.db.ExecContext(t.Context(), `DROP TRIGGER block_private_intent`); err != nil {
		t.Fatal(err)
	}
	committed := parseConfigurationResponse(t, f.request(t, "POST", targetPath, f.proof, struct{}{}, 200))
	if committed.State != "committed" {
		t.Fatal("configuration journal not committed")
	}
	var count int
	if err = f.s.db.QueryRowContext(t.Context(), `SELECT count(*) FROM configuration_changes`).Scan(&count); err != nil || count != 0 {
		t.Fatal("configuration payload leaked into private journal", err)
	}
	if err = f.s.db.QueryRowContext(t.Context(), `SELECT count(*) FROM management_security_events WHERE event='configuration.change_authorized'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("durable intent missing", err)
	}
	targets := f.request(t, "GET", "/changes/targets", f.proof, nil, 200).Body.String()
	if !strings.Contains(targets, `"kind":"route-order","store":"configuration"`) {
		t.Fatal("order target was assigned to the wrong store")
	}
	// A resource cannot be redirected to the other store by caller input.
	request["store"] = "identity"
	f.request(t, "POST", "/changes", f.proof, request, 400)
}
