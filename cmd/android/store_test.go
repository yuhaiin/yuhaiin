package yuhaiin

import (
	"context"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/schema/tools"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestStore(t *testing.T) {
	SetSavePath(t.TempDir())
	GetStore().PutFloat("float", 3.1415926)
	t.Log(GetStore().GetFloat("float"))
	assert.Equal(t, float32(3.1415926), GetStore().GetFloat("float"))
}

func TestMultipleProcess(t *testing.T) {
	SetSavePath(t.TempDir())
	GetStore().PutFloat("float", 3.1415926)
	t.Log(GetStore().GetFloat("float"))
}

func TestSQLitePreferenceStore(t *testing.T) {
	dir := t.TempDir()
	SetSavePath(dir)

	GetStore().PutString("profile", "balanced")
	GetStore().PutBoolean("allow_lan_test", true)
	GetStore().PutInt("port_test", 1234)

	assert.Equal(t, "balanced", GetStore().GetString("profile"))
	assert.Equal(t, true, GetStore().GetBoolean("allow_lan_test"))
	assert.Equal(t, int32(1234), GetStore().GetInt("port_test"))

	store, err := storagesqlite.Open(context.Background(), tools.PathGenerator.State(dir))
	assert.NoError(t, err)
	defer store.Close()

	var valueJSON string
	err = store.DB().QueryRowContext(context.Background(), `
		SELECT value_json
		FROM android_extra_preferences
		WHERE key = 'profile'
	`).Scan(&valueJSON)
	assert.NoError(t, err)
	assert.Equal(t, `"balanced"`, valueJSON)
}
