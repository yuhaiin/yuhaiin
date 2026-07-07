package yuhaiin

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

var (
	legacyPreferenceStore = newMemoryStore(filepath.Join(savepath, "yuhaiin_memory_store.json"), true)
	appStore              Store
)

type singleStore[k comparable, v any] struct {
	Values   map[k]v `json:"values"`
	readonly bool
	mu       sync.RWMutex
}

func newSingleStore[k comparable, v any](readonly bool) *singleStore[k, v] {
	s := &singleStore[k, v]{readonly: readonly}
	s.init()
	return s
}

func (s *singleStore[k, v]) Put(key k, value v) {
	if s.readonly {
		return
	}

	s.mu.Lock()
	s.Values[key] = value
	s.mu.Unlock()
}

func (s *singleStore[K, V]) Get(key K) (V, bool) {
	s.mu.RLock()
	v, ok := s.Values[key]
	s.mu.RUnlock()
	return v, ok
}

func (s *singleStore[k, v]) init() {
	if s.Values == nil {
		s.Values = make(map[k]v)
	}
}

type memoryStore struct {
	Strings  *singleStore[string, string]  `json:"strings"`
	Ints     *singleStore[string, int32]   `json:"ints"`
	Bools    *singleStore[string, bool]    `json:"bools"`
	Longs    *singleStore[string, int64]   `json:"longs"`
	Floats   *singleStore[string, float32] `json:"floats"`
	Bytes    *singleStore[string, []byte]  `json:"bytes"`
	readonly bool
	Path     string `json:"path"`
}

func newMemoryStore(path string, readOnly bool) *memoryStore {
	m := &memoryStore{
		Strings:  newSingleStore[string, string](readOnly),
		Ints:     newSingleStore[string, int32](readOnly),
		Bools:    newSingleStore[string, bool](readOnly),
		Longs:    newSingleStore[string, int64](readOnly),
		Floats:   newSingleStore[string, float32](readOnly),
		Bytes:    newSingleStore[string, []byte](readOnly),
		readonly: readOnly,
		Path:     path,
	}

	data, err := os.ReadFile(path)
	if err == nil && len(data) > 0 {
		err = json.Unmarshal(data, m)
		if err != nil {
			log.Error("unmarshal memory store failed", "err", err)
		}
	}

	return m
}

func (m *memoryStore) Save() {
	if m.readonly {
		return
	}

	data, err := json.Marshal(m)
	if err != nil {
		log.Error("marshal memory store failed", "err", err)
		return
	}

	if err = os.WriteFile(m.Path, data, 0644); err != nil {
		log.Error("write memory store to file failed", "err", err)
	}
}

func (m *memoryStore) PutString(key string, value string) {
	m.Strings.Put(key, value)
	m.Save()
}

func (m *memoryStore) PutInt(key string, value int32) {
	m.Ints.Put(key, value)
	m.Save()
}

func (m *memoryStore) PutBoolean(key string, value bool) {
	m.Bools.Put(key, value)
	m.Save()
}

func (m *memoryStore) PutLong(key string, value int64) {
	m.Longs.Put(key, value)
	m.Save()
}

func (m *memoryStore) PutFloat(key string, value float32) {
	m.Floats.Put(key, value)
	m.Save()
}

func (m *memoryStore) GetString(key string) string {
	str, ok := m.Strings.Get(key)
	if !ok {
		return defaultStringValue[key]
	}
	return str
}

func (m *memoryStore) GetInt(key string) int32 {
	v, ok := m.Ints.Get(key)
	if !ok {
		return defaultIntValue[key]
	}
	return v
}

func (m *memoryStore) GetBoolean(key string) bool {
	v, ok := m.Bools.Get(key)
	if !ok {
		return defaultBoolValue[key]
	}

	return v
}

func (m *memoryStore) GetLong(key string) int64 {
	v, _ := m.Longs.Get(key)
	return v
}

func (m *memoryStore) GetFloat(key string) float32 {
	v, _ := m.Floats.Get(key)
	return v
}

func (m *memoryStore) GetBytes(key string) []byte {
	v, _ := m.Bytes.Get(key)
	return v
}

func (m *memoryStore) PutBytes(key string, value []byte) {
	m.Bytes.Put(key, value)
	m.Save()
}

type Store interface {
	PutString(key string, value string)
	PutInt(key string, value int32)
	PutBoolean(key string, value bool)
	PutLong(key string, value int64)
	PutFloat(key string, value float32)
	GetString(key string) string
	GetInt(key string) int32
	GetBoolean(key string) bool
	GetLong(key string) int64
	GetFloat(key string) float32
	GetBytes(key string) []byte
	PutBytes(key string, value []byte)
}

func GetStore() Store {
	if appStore != nil {
		return appStore
	}
	return legacyPreferenceStore
}

type sqlitePreferenceStore struct {
	path     string
	fallback *memoryStore
	mu       sync.Mutex
}

func newSQLitePreferenceStore(path string, fallback *memoryStore) *sqlitePreferenceStore {
	return &sqlitePreferenceStore{path: path, fallback: fallback}
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
	value, ok := getSQLitePreference[int64](s, key)
	if !ok {
		return 0
	}
	return value
}

func (s *sqlitePreferenceStore) GetFloat(key string) float32 {
	value, ok := getSQLitePreference[float32](s, key)
	if !ok {
		return 0
	}
	return value
}

func (s *sqlitePreferenceStore) GetBytes(key string) []byte {
	value, ok := getSQLitePreference[[]byte](s, key)
	if !ok {
		return nil
	}
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
		if err != nil {
			return fmt.Errorf("upsert android preference %q failed: %w", key, err)
		}
		return nil
	}); err != nil {
		log.Error("put sqlite android preference failed", "key", key, "err", err)
	}
}

func getSQLitePreference[T any](s *sqlitePreferenceStore, key string) (T, bool) {
	var value T
	err := s.withDB(func(ctx context.Context, db *sql.DB) error {
		var data string
		err := db.QueryRowContext(ctx, `
			SELECT value_json
			FROM android_extra_preferences
			WHERE key = ?
		`, key).Scan(&data)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return sql.ErrNoRows
		case err != nil:
			return fmt.Errorf("query android preference %q failed: %w", key, err)
		}

		if err := json.Unmarshal([]byte(data), &value); err != nil {
			return fmt.Errorf("decode android preference %q failed: %w", key, err)
		}
		return nil
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
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	store, err := storagesqlite.Open(ctx, s.path)
	if err != nil {
		return fmt.Errorf("open android preference sqlite failed: %w", err)
	}
	defer store.Close()

	if err := s.ensureImported(ctx, store.DB()); err != nil {
		return err
	}

	return fn(ctx, store.DB())
}

func (s *sqlitePreferenceStore) ensureImported(ctx context.Context, db *sql.DB) error {
	done, err := s.loadMetadata(ctx, db, "legacy_android_preferences_import_done")
	if err != nil {
		return err
	}
	if done == "1" {
		return nil
	}

	var existing int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM android_extra_preferences`).Scan(&existing); err != nil {
		return fmt.Errorf("count android preferences failed: %w", err)
	}
	if existing > 0 {
		return s.updateMetadata(ctx, db, map[string]string{
			"legacy_android_preferences_import_done":   "1",
			"legacy_android_preferences_import_source": "existing_sqlite",
		})
	}

	source := "missing"
	if s.fallback != nil {
		if err := s.importMemoryStore(ctx, db, s.fallback); err != nil {
			return err
		}
		source = filepath.Base(s.fallback.Path)
	}

	return s.updateMetadata(ctx, db, map[string]string{
		"legacy_android_preferences_import_done":   "1",
		"legacy_android_preferences_import_source": source,
	})
}

func (s *sqlitePreferenceStore) importMemoryStore(ctx context.Context, db *sql.DB, store *memoryStore) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin android preference import transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().Unix()
	for key, value := range store.Strings.Values {
		if err := insertAndroidPreference(ctx, tx, key, value, now); err != nil {
			return err
		}
	}
	for key, value := range store.Ints.Values {
		if err := insertAndroidPreference(ctx, tx, key, value, now); err != nil {
			return err
		}
	}
	for key, value := range store.Bools.Values {
		if err := insertAndroidPreference(ctx, tx, key, value, now); err != nil {
			return err
		}
	}
	for key, value := range store.Longs.Values {
		if err := insertAndroidPreference(ctx, tx, key, value, now); err != nil {
			return err
		}
	}
	for key, value := range store.Floats.Values {
		if err := insertAndroidPreference(ctx, tx, key, value, now); err != nil {
			return err
		}
	}
	for key, value := range store.Bytes.Values {
		if err := insertAndroidPreference(ctx, tx, key, value, now); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit android preference import transaction failed: %w", err)
	}
	return nil
}

func insertAndroidPreference(ctx context.Context, tx *sql.Tx, key string, value any, now int64) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal android preference %q failed: %w", key, err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO android_extra_preferences(key, value_json, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(key) DO NOTHING
	`, key, string(data), now); err != nil {
		return fmt.Errorf("insert android preference %q failed: %w", key, err)
	}
	return nil
}

func (s *sqlitePreferenceStore) loadMetadata(ctx context.Context, db *sql.DB, key string) (string, error) {
	var value string
	err := db.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key = ?`, key).Scan(&value)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("load android preference metadata %q failed: %w", key, err)
	default:
		return value, nil
	}
}

func (s *sqlitePreferenceStore) updateMetadata(ctx context.Context, db *sql.DB, values map[string]string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin android preference metadata transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for key, value := range values {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO metadata(key, value)
			VALUES (?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value
		`, key, value); err != nil {
			return fmt.Errorf("update android preference metadata %q failed: %w", key, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit android preference metadata transaction failed: %w", err)
	}
	return nil
}

func ifOr[T any](a bool, b, c T) T {
	if a {
		return b
	}
	return c
}
