package yuhaiin

import (
	"encoding/binary"
	"encoding/json/v2"
	"math"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/cache"
	"github.com/Asutorufa/yuhaiin/pkg/cache/share"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/proto"
)

func dbPath() string       { return filepath.Join(savepath, "yuhaiin.db") }
func badgerDBPath() string { return filepath.Join(savepath, "yuhaiin.badger.db") }
func socketPath() string   { return filepath.Join(datadir, "kv.sock") }

var (
	shareDB     *share.ShareDB
	shareDBOnce sync.Once
	memoryDB    = newMemoryStore(filepath.Join(savepath, "yuhaiin_memory_store.json"), true)
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

func (s *singleStore[K, V]) Get(key K) V {
	s.mu.RLock()
	v := s.Values[key]
	s.mu.RUnlock()
	return v
}

func (s *singleStore[k, v]) init() {
	if s.Values == nil {
		s.Values = make(map[k]v)
	}
}

type memoryStore struct {
	Strings   *singleStore[string, string]  `json:"strings"`
	Ints      *singleStore[string, int32]   `json:"ints"`
	Bools     *singleStore[string, bool]    `json:"bools"`
	Longs     *singleStore[string, int64]   `json:"longs"`
	Floats    *singleStore[string, float32] `json:"floats"`
	Bytes     *singleStore[string, []byte]  `json:"bytes"`
	readlonly bool
	Path      string `json:"path"`
}

func newMemoryStore(path string, readOnly bool) *memoryStore {
	m := &memoryStore{
		Strings:   newSingleStore[string, string](readOnly),
		Ints:      newSingleStore[string, int32](readOnly),
		Bools:     newSingleStore[string, bool](readOnly),
		Longs:     newSingleStore[string, int64](readOnly),
		Floats:    newSingleStore[string, float32](readOnly),
		Bytes:     newSingleStore[string, []byte](readOnly),
		readlonly: readOnly,
		Path:      path,
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
	if m.readlonly {
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
	return m.Strings.Get(key)
}

func (m *memoryStore) GetInt(key string) int32 {
	return m.Ints.Get(key)
}

func (m *memoryStore) GetBoolean(key string) bool {
	return m.Bools.Get(key)
}

func (m *memoryStore) GetLong(key string) int64 {
	return m.Longs.Get(key)
}

func (m *memoryStore) GetFloat(key string) float32 {
	return m.Floats.Get(key)
}

func (m *memoryStore) GetBytes(key string) []byte {
	return m.Bytes.Get(key)
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

type storeImpl struct {
	db cache.Cache
}

func newStore(batch string) Store {
	shareDBOnce.Do(func() {
		shareDB = share.NewShareCache(dbPath(), badgerDBPath(), socketPath())
	})

	return &storeImpl{db: share.NewCache(shareDB, batch)}
}

func (s *storeImpl) PutString(key string, value string) {
	_ = s.db.Put([]byte(key), []byte(value))
	memoryDB.PutString(key, value)
}

func (s *storeImpl) PutInt(key string, value int32) {
	bytes := binary.NativeEndian.AppendUint32(nil, uint32(value))
	_ = s.db.Put([]byte(key), bytes)
	memoryDB.PutInt(key, value)
}

func (s *storeImpl) PutBoolean(key string, value bool) {
	_ = s.db.Put([]byte(key), ifOr(value, []byte{1}, []byte{0}))
	memoryDB.PutBoolean(key, value)
}

func (s *storeImpl) PutLong(key string, value int64) {
	bytes := binary.NativeEndian.AppendUint64(nil, uint64(value))
	_ = s.db.Put([]byte(key), bytes)
	memoryDB.PutLong(key, value)
}

func (s *storeImpl) PutFloat(key string, value float32) {
	bytes := binary.NativeEndian.AppendUint32(nil, math.Float32bits(value))
	_ = s.db.Put([]byte(key), bytes)
	memoryDB.PutFloat(key, value)
}

func (s *storeImpl) PutBytes(key string, value []byte) {
	_ = s.db.Put([]byte(key), value)
	memoryDB.PutBytes(key, value)
}

func (s *storeImpl) GetString(key string) string {
	bytes, _ := s.db.Get([]byte(key))
	if bytes == nil {
		return defaultStringValue[key]
	}
	memoryDB.PutString(key, string(bytes))
	return string(bytes)
}

func (s *storeImpl) GetBytes(key string) []byte {
	bytes, _ := s.db.Get([]byte(key))
	memoryDB.PutBytes(key, bytes)
	return bytes
}

func (s *storeImpl) GetInt(key string) int32 {
	bytes, _ := s.db.Get([]byte(key))
	if len(bytes) < 4 || bytes == nil {
		return defaultIntValue[key]
	}

	value := binary.NativeEndian.Uint32(bytes)
	memoryDB.PutInt(key, int32(value))
	return int32(value)
}

func (s *storeImpl) GetBoolean(key string) bool {
	bytes, _ := s.db.Get([]byte(key))
	if len(bytes) == 0 || bytes == nil {
		return defaultBoolValue[key] == 1
	}

	memoryDB.PutBoolean(key, bytes[0] == 1)
	return bytes[0] == 1
}

func (s *storeImpl) GetLong(key string) int64 {
	bytes, _ := s.db.Get([]byte(key))
	if len(bytes) < 8 || bytes == nil {
		return defaultLongValue[key]
	}

	value := binary.NativeEndian.Uint64(bytes)
	memoryDB.PutLong(key, int64(value))
	return int64(value)
}

func (s *storeImpl) GetFloat(key string) float32 {
	bytes, _ := s.db.Get([]byte(key))
	if len(bytes) < 4 || bytes == nil {
		return defaultFloatValue[key]
	}
	memoryDB.PutFloat(key, math.Float32frombits(binary.NativeEndian.Uint32(bytes)))
	return math.Float32frombits(binary.NativeEndian.Uint32(bytes))
}

func (s *storeImpl) GetStringMap(key string) map[string]string {
	bytes, _ := s.db.Get([]byte(key))
	if len(bytes) == 0 {
		return map[string]string{}
	}

	var resp map[string]string
	if err := json.Unmarshal(bytes, &resp); err != nil {
		log.Error("unmarshal string map failed", "key", key, "err", err)
		return nil
	}

	return resp
}

var (
	storeOnce = &sync.Once{}
	store     Store
)

func GetStore() Store {
	storeOnce.Do(func() { store = newStore("Default") })
	return store
}

func CloseStore() {
	if shareDB == nil {
		return
	}

	shareDB.Close()
}

type configDB[T proto.Message] struct {
	setting    T
	getDefault func(*pc.Setting) T
	toSetting  func(T) *pc.Setting
	dbName     string
	mu         sync.RWMutex
	inited     atomic.Bool
}

func newConfigDB[T proto.Message](dbName string, getDefault func(*pc.Setting) T, toSetting func(T) *pc.Setting) *configDB[T] {
	return &configDB[T]{
		getDefault: getDefault,
		toSetting:  toSetting,
		dbName:     dbName,
	}
}

func (b *configDB[T]) initSetting() {
	if b.inited.Load() {
		return
	}

	s := GetStore().GetBytes(b.dbName)

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
	GetStore().PutBytes(b.dbName, s)
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

func (b *configDB[T]) Dir() string { return filepath.Dir(dbPath()) }

func ifOr[T any](a bool, b, c T) T {
	if a {
		return b
	}
	return c
}
