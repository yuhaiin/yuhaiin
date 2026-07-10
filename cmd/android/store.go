package yuhaiin

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

var appStore Store = &sqlitePreferenceStore{}

type Store interface {
	PutString(key string, value string)
	PutInt(key string, value int32)
	PutBoolean(key string, value bool)
	PutLong(key string, value int64)
	PutFloat(key string, value float32)
	PutBytes(key string, value []byte)
	GetString(key string) string
	GetInt(key string) int32
	GetBoolean(key string) bool
	GetLong(key string) int64
	GetFloat(key string) float32
	GetBytes(key string) []byte
}

func GetStore() Store { return appStore }

// sqlitePreferenceStore is deliberately a thin typed facade over the shared
// application database. Legacy Android JSON is imported during StateDB.Migrate,
// before this store is used by App.Start.
type sqlitePreferenceStore struct {
	path string
}

func newSQLitePreferenceStore(path string) *sqlitePreferenceStore {
	return &sqlitePreferenceStore{path: path}
}

func (s *sqlitePreferenceStore) PutString(key string, value string) { s.put(key, value) }
func (s *sqlitePreferenceStore) PutInt(key string, value int32)     { s.put(key, value) }
func (s *sqlitePreferenceStore) PutBoolean(key string, value bool)  { s.put(key, value) }
func (s *sqlitePreferenceStore) PutLong(key string, value int64)    { s.put(key, value) }
func (s *sqlitePreferenceStore) PutFloat(key string, value float32) { s.put(key, value) }
func (s *sqlitePreferenceStore) PutBytes(key string, value []byte)  { s.put(key, value) }

func (s *sqlitePreferenceStore) GetString(key string) string {
	value, ok := getSQLitePreference[string](s, key)
	if !ok {
		return defaultStringValue[key]
	}
	return value
}

func (s *sqlitePreferenceStore) GetInt(key string) int32 {
	value, ok := getSQLitePreference[int32](s, key)
	if !ok {
		return defaultIntValue[key]
	}
	return value
}

func (s *sqlitePreferenceStore) GetBoolean(key string) bool {
	value, ok := getSQLitePreference[bool](s, key)
	if !ok {
		return defaultBoolValue[key]
	}
	return value
}

func (s *sqlitePreferenceStore) GetLong(key string) int64 {
	value, _ := getSQLitePreference[int64](s, key)
	return value
}

func (s *sqlitePreferenceStore) GetFloat(key string) float32 {
	value, _ := getSQLitePreference[float32](s, key)
	return value
}

func (s *sqlitePreferenceStore) GetBytes(key string) []byte {
	value, _ := getSQLitePreference[[]byte](s, key)
	return value
}

func (s *sqlitePreferenceStore) put(key string, value any) {
	if err := s.withDB(func(ctx context.Context, db *sql.DB) error {
		data, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("marshal android preference %q failed: %w", key, err)
		}
		_, err = db.ExecContext(ctx, `
			INSERT INTO android_extra_preferences(key, value_json, updated_at)
			VALUES (?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET
				value_json = excluded.value_json,
				updated_at = excluded.updated_at
		`, key, string(data), time.Now().Unix())
		return err
	}); err != nil {
		log.Error("put sqlite android preference failed", "key", key, "err", err)
	}
}

func getSQLitePreference[T any](s *sqlitePreferenceStore, key string) (T, bool) {
	var value T
	err := s.withDB(func(ctx context.Context, db *sql.DB) error {
		var data string
		if err := db.QueryRowContext(ctx, `
			SELECT value_json FROM android_extra_preferences WHERE key = ?
		`, key).Scan(&data); err != nil {
			return err
		}
		return json.Unmarshal([]byte(data), &value)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return value, false
	}
	if err != nil {
		log.Error("get sqlite android preference failed", "key", key, "err", err)
		return value, false
	}
	return value, true
}

func (s *sqlitePreferenceStore) withDB(fn func(context.Context, *sql.DB) error) error {
	if s == nil || s.path == "" {
		return errors.New("android preference store is not initialized")
	}
	ctx := context.Background()
	store, err := storagesqlite.Open(ctx, s.path)
	if err != nil {
		return fmt.Errorf("open android preference sqlite failed: %w", err)
	}
	defer store.Close()
	return fn(ctx, store.DB())
}

func ifOr[T any](a bool, b, c T) T {
	if a {
		return b
	}
	return c
}
