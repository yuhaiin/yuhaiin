package backup

import (
	"fmt"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/paths"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

// This fixture measures snapshot and sanitization, not network upload or large
// production databases. Runtime rows and the legacy FTS index are deliberate.
func BenchmarkConfigurationSnapshot(b *testing.B) {
	directory := b.TempDir()
	db, err := storagesqlite.Open(b.Context(), paths.PathGenerator.State(directory))
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	tx, err := db.DB().BeginTx(b.Context(), nil)
	if err != nil {
		b.Fatal(err)
	}
	for i := range 1000 {
		if _, err := tx.ExecContext(b.Context(), `INSERT INTO nodes(hash,group_name,name,origin,search_text,updated_at,data_json) VALUES(?,?,?,1,?,1,'{}')`, fmt.Sprint(i), "fixture", fmt.Sprintf("node-%d", i), "fixture search"); err != nil {
			b.Fatal(err)
		}
		id := fmt.Sprintf("node-%d", i)
		data := fmt.Sprintf(`{"id":%q,"name":%q,"origin":"manual","enabled":true,"chain":[{"type":"direct","direct":{}}]}`, id, id)
		if _, err := tx.ExecContext(b.Context(), `INSERT INTO nodes_v2(id,name,group_name,origin,enabled,chain_types_json,updated_at,data_json) VALUES(?,?,?,'manual',1,'["direct"]',1,?)`, id, id, "fixture", data); err != nil {
			b.Fatal(err)
		}
	}
	for i := range 10000 {
		if _, err := tx.ExecContext(b.Context(), `INSERT INTO gateway_statistics(gateway_id,requests,updated_at) VALUES(?,1,1)`, fmt.Sprint(i)); err != nil {
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	backup := &Backup{dir: directory}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		snapshot, err := backup.snapshotStateDB(b.Context())
		if err != nil {
			b.Fatal(err)
		}
		if err := snapshot.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
