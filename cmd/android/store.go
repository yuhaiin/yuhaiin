package yuhaiin

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/cache/badger"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/proto"
)

var (
	memoryDB       = newMemoryStore(filepath.Join(savepath, "yuhaiin_memory_store.json"), true)
	memoryConfigDB = newMemoryStore(filepath.Join(savepath, "yuhaiin_memory_config_store.json"), true)
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
	switch key {
	case NewYuhaiinPortKey:
		if m.Path != memoryConfigDB.Path {
			return newMemoryStore(memoryConfigDB.Path, true).GetInt(key)
		}
	}
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

func GetStore() Store { return memoryDB }

type configDB[T proto.Message] struct {
	setting    T
	getDefault func(*pc.Setting) T
	toSetting  func(T) *pc.Setting
	dbName     string
	mu         sync.RWMutex
	inited     atomic.Bool

	store *memoryStore
}

func newConfigDB[T proto.Message](
	store *memoryStore,
	dbName string,
	getDefault func(*pc.Setting) T,
	toSetting func(T) *pc.Setting,
) *configDB[T] {
	return &configDB[T]{
		store:      store,
		getDefault: getDefault,
		toSetting:  toSetting,
		dbName:     dbName,
	}
}

func (b *configDB[T]) initSetting() {
	if b.inited.Load() {
		return
	}

	s := b.store.GetBytes(b.dbName)

	config := b.getDefault(pc.DefaultSetting(b.Dir()))
	if len(s) > 0 {
		err := proto.Unmarshal(s, config)
		if err != nil {
			log.Error("unmarshal failed", "err", err)
		}
	}

	b.inited.Store(true)
	b.setting = config
}

func (b *configDB[T]) Batch(f ...func(*pc.Setting) error) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.initSetting()

	setting := b.toSetting(b.setting)
	for i := range f {
		if err := f[i](setting); err != nil {
			return err
		}
	}

	s, err := proto.Marshal(b.getDefault(setting))
	if err != nil {
		return err
	}

	b.setting = b.getDefault(setting)
	b.store.PutBytes(b.dbName, s)
	return nil
}

func (b *configDB[T]) View(f ...func(*pc.Setting) error) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	b.initSetting()

	setting := b.toSetting(b.setting)

	for i := range f {
		if err := f[i](proto.CloneOf(setting)); err != nil {
			return err
		}
	}

	return nil
}

func (b *configDB[T]) Dir() string { return savepath }

func ifOr[T any](a bool, b, c T) T {
	if a {
		return b
	}
	return c
}

func migrate(badgerPath string, dst, configDst string) {
	ms := newMemoryStore(dst, false)
	ms2 := newMemoryStore(configDst, false)

	if ms.GetBoolean("MIGRATED") {
		return
	}

	_, err := os.Stat(badgerPath)
	if err != nil {
		return
	}

	bc, err := badger.New(badgerPath)
	if err != nil {
		log.Warn("badger open failed", "err", err)
		return
	}
	defer bc.Close()

	bc.NewCache("yuhaiin", "Default").Range(func(key, value []byte) bool {
		switch string(value) {
		case "bypass_db", "inbound_db", "backup_db", "resolver_db", "chore_db":
			ms2.PutBytes(string(key), value)
			return true
		}
		if len(value) == 1 && value[0] == 1 {
			ms.PutBoolean(string(key), true)
		} else {
			ms.PutString(string(key), string(value))
		}

		return true
	})

	ms.PutBoolean("MIGRATED", true)
}
