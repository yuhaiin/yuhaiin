package migrate

import "github.com/Asutorufa/yuhaiin/pkg/legacy/chore"

func NewStateDB(path string) *chore.SqliteDB {
	return chore.NewExplicitMigrationSqliteDB(path)
}
