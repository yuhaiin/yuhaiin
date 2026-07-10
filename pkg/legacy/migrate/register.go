package migrate

import (
	"context"
	"database/sql"

	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/legacy/chore"
	"github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
)

func init() {
	chore.RegisterPlainMigrationHooks(chore.PlainMigrationHooks{
		MigrateLegacyInbounds: func(ctx context.Context, db *sql.DB, updatedAt int64) ([]chore.PlainMigrationWarning, error) {
			warnings, err := MigrateLegacyInbounds(ctx, db, updatedAt)
			return choreWarnings(warnings), err
		},
		ImportLegacyNodes:          ImportLegacyNodesFromJSON,
		MigrateLegacyNodes:         MigrateLegacyNodes,
		MigrateLegacySubscriptions: MigrateLegacySubscriptions,
		MigrateLegacyResolvers:     MigrateLegacyResolvers,
		MigrateLegacyRouteRules:    MigrateLegacyRouteRules,
		MigrateLegacyRouteLists:    MigrateLegacyRouteLists,
		MigrateLegacyRouteTags:     MigrateLegacyRouteTags,
		ConvertLegacyInbound: func(name string, inbound *config.Inbound) (contractinbound.Inbound, []chore.PlainMigrationWarning, error) {
			converted, warnings, err := ConvertLegacyInbound(name, inbound)
			return converted, choreWarnings(warnings), err
		},
	})
}

func choreWarnings(in []Warning) []chore.PlainMigrationWarning {
	out := make([]chore.PlainMigrationWarning, 0, len(in))
	for _, warning := range in {
		out = append(out, chore.PlainMigrationWarning{
			Entity:  warning.Entity,
			Message: warning.Message,
		})
	}
	return out
}
