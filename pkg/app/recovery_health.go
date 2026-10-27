package app

import (
	"context"
	"errors"

	"github.com/Asutorufa/yuhaiin/pkg/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
)

// RecoveryStartupHealth checks the actual initialized owners. It does not
// generate outbound traffic or claim that arbitrary VPN peers are reachable.
func (a *AppInstance) RecoveryStartupHealth(ctx context.Context) error {
	if a.StateStore == nil || a.Inbound == nil || a.Mux == nil {
		return errors.New("restored application owners are unavailable")
	}
	db, err := a.StateStore.SQLDB(ctx)
	if err != nil {
		return err
	}
	if err := db.PingContext(ctx); err != nil {
		return err
	}
	var version int
	if err := db.QueryRowContext(ctx, "SELECT CAST(value AS INTEGER) FROM metadata WHERE key='schema_version'").Scan(&version); err != nil {
		return err
	}
	expected, err := sqlite.SupportedSchemaVersion("configuration")
	if err != nil || version != expected {
		return errors.New("restored database did not finish its supported migrations")
	}
	statuses, err := inbound.NewContractStore(store.NewInboundStore(db), a.Inbound).Statuses(ctx)
	if err != nil {
		return err
	}
	for _, status := range statuses {
		if status.Enabled && status.Status != "running" {
			return errors.New("a restored inbound failed to become ready")
		}
	}
	if a.Gateway != nil {
		status := a.Gateway.Status()
		if status.StartupError != "" || status.Revision != a.Gateway.Config().Revision {
			return errors.New("restored gateway configuration did not become effective")
		}
	}
	return nil
}
