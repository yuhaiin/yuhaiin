package yuhaiin

import (
	"encoding/binary"
	"math"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache/share"
	"github.com/go-json-experiment/json"
	"google.golang.org/protobuf/proto"
)

func dbPath() string     { return filepath.Join(savepath, "yuhaiin.db") }
func socketPath() string { return filepath.Join(datadir, "kv.sock") }

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
	Close() error
}

type storeImpl struct {
	db cache.Cache
}

func newStore(batch string) Store {
	return &storeImpl{db: share.NewShareCache(dbPath(), socketPath(), batch)}
}

func (s *storeImpl) Close() error { return s.db.Close() }

func (s *storeImpl) PutString(key string, value string) {
	_ = s.db.Put(cache.Element([]byte(key), []byte(value)))
}

func (s *storeImpl) PutInt(key string, value int32) {
	bytes := binary.NativeEndian.AppendUint32(nil, uint32(value))
	_ = s.db.Put(cache.Element([]byte(key), bytes))
}

func (s *storeImpl) PutBoolean(key string, value bool) {
	_ = s.db.Put(cache.Element([]byte(key), ifOr(value, []byte{1}, []byte{0})))
}

func (s *storeImpl) PutLong(key string, value int64) {
	bytes := binary.NativeEndian.AppendUint64(nil, uint64(value))
	_ = s.db.Put(cache.Element([]byte(key), bytes))
}

func (s *storeImpl) PutFloat(key string, value float32) {
	bytes := binary.NativeEndian.AppendUint32(nil, math.Float32bits(value))
	_ = s.db.Put(cache.Element([]byte(key), bytes))
}

func (s *storeImpl) PutBytes(key string, value []byte) {
	_ = s.db.Put(cache.Element([]byte(key), value))
}

func (s *storeImpl) GetString(key string) string {
	bytes, _ := s.db.Get([]byte(key))
	if bytes == nil {
		return defaultStringValue[key]
	}
	return string(bytes)
}

func (s *storeImpl) GetBytes(key string) []byte {
	bytes, _ := s.db.Get([]byte(key))
	return bytes
}

func (s *storeImpl) GetInt(key string) int32 {
	bytes, _ := s.db.Get([]byte(key))
	if len(bytes) < 4 || bytes == nil {
		return defaultIntValue[key]
	}

	value := binary.NativeEndian.Uint32(bytes)
	return int32(value)
}

func (s *storeImpl) GetBoolean(key string) bool {
	bytes, _ := s.db.Get([]byte(key))
	if len(bytes) == 0 || bytes == nil {
		return defaultBoolValue[key] == 1
	}

	return bytes[0] == 1
}

func (s *storeImpl) GetLong(key string) int64 {
	bytes, _ := s.db.Get([]byte(key))
	if len(bytes) < 8 || bytes == nil {
		return defaultLongValue[key]
	}

	value := binary.NativeEndian.Uint64(bytes)

	return int64(value)
}

func (s *storeImpl) GetFloat(key string) float32 {
	bytes, _ := s.db.Get([]byte(key))
	if len(bytes) < 4 || bytes == nil {
		return defaultFloatValue[key]
	}
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
	storeMu sync.RWMutex
	store   Store
)

func GetStore() Store {
	storeMu.RLock()
	s := store
	storeMu.RUnlock()

	if s != nil {
		return s
	}

	storeMu.Lock()
	defer storeMu.Unlock()

	if store != nil {
		return store
	}

	store = newStore("Default")
	return store
}

func CloseStore() {
	storeMu.Lock()
	defer storeMu.Unlock()

	if store == nil {
		return
	}

	store.Close()
	store = nil
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
