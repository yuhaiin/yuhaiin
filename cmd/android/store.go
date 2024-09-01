package yuhaiin

import (
	"encoding/binary"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	cb "github.com/Asutorufa/yuhaiin/pkg/utils/cache/bbolt"
	"go.etcd.io/bbolt"
)

var dbPath string
var db *cb.Cache
var mu sync.Mutex

func InitDB(path string) error {
	dbPath = filepath.Join(path, "yuhaiin.db")
	return nil
}

func initDB() *cb.Cache {
	if db != nil {
		return db
	}

	mu.Lock()
	defer mu.Unlock()

	if db != nil {
		return db
	}

	log.Info("init global db", "path", dbPath)

	odb, err := bbolt.Open(dbPath, os.ModePerm, &bbolt.Options{
		Timeout: time.Second * 2,
	})
	if err != nil {
		panic(err)
	}

	db = cb.NewCache(odb, "yuhaiin")
	return db
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
	Dump() []byte
}

type storeImpl struct {
	batch string
	db    cache.Cache
	mu    sync.RWMutex
}

func (s *storeImpl) initDB() {
	s.mu.RLock()
	if s.db != nil {
		s.mu.RUnlock()
		return
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		return
	}

	s.db = initDB().NewCache(s.batch)
}

func (s *storeImpl) PutString(key string, value string) {
	s.initDB()
	s.db.Put([]byte(key), []byte(value))
}

func (s *storeImpl) PutInt(key string, value int32) {
	s.initDB()
	bytes := binary.NativeEndian.AppendUint32(nil, uint32(value))
	s.db.Put([]byte(key), bytes)
}

func (s *storeImpl) PutBoolean(key string, value bool) {
	s.initDB()
	if value {
		s.db.Put([]byte(key), []byte{1})
	} else {
		s.db.Put([]byte(key), []byte{0})
	}
}

func (s *storeImpl) PutLong(key string, value int64) {
	s.initDB()
	bytes := binary.NativeEndian.AppendUint64(nil, uint64(value))
	s.db.Put([]byte(key), bytes)
}

func (s *storeImpl) PutFloat(key string, value float32) {
	s.initDB()
	bytes := binary.NativeEndian.AppendUint32(nil, math.Float32bits(value))
	s.db.Put([]byte(key), bytes)
}

func (s *storeImpl) GetString(key string) string {
	s.initDB()
	bytes := s.db.Get([]byte(key))
	if bytes == nil {
		return defaultStringValue[key]
	}
	return string(bytes)
}

func (s *storeImpl) GetInt(key string) int32 {
	s.initDB()
	bytes := s.db.Get([]byte(key))
	if len(bytes) < 4 || bytes == nil {
		return defaultIntValue[key]
	}

	value := binary.NativeEndian.Uint32(bytes)
	return int32(value)
}

func (s *storeImpl) GetBoolean(key string) bool {
	s.initDB()
	bytes := s.db.Get([]byte(key))
	if len(bytes) == 0 || bytes == nil {
		return defaultBoolValue[key] == 1
	}

	return bytes[0] == 1
}

func (s *storeImpl) GetLong(key string) int64 {
	s.initDB()
	bytes := s.db.Get([]byte(key))
	if len(bytes) < 8 || bytes == nil {
		return defaultLangValue[key]
	}

	value := binary.NativeEndian.Uint64(bytes)

	return int64(value)
}
func (s *storeImpl) GetFloat(key string) float32 {
	s.initDB()
	bytes := s.db.Get([]byte(key))
	if len(bytes) < 4 || bytes == nil {
		return defaultFloatValue[key]
	}
	return math.Float32frombits(binary.NativeEndian.Uint32(bytes))
}

func (s *storeImpl) Dump() []byte {
	s.initDB()
	var data = map[string][]byte{}

	for k, v := range s.db.Range {
		data[string(k)] = v
	}

	bytes, _ := json.Marshal(data)
	return bytes
}

func GetStore(prefix string) Store {
	return &storeImpl{batch: prefix}
}

func CloseStore() {
	mu.Lock()
	defer mu.Unlock()

	if db != nil {
		db.Close()
		db = nil
	}
}

// func GetStores() []byte {
// 	var stores []string
// 	db.Range(func(k, v []byte) bool {
// 		stores = append(stores, string(k))
// 		return true
// 	})

// 	data, _ := json.Marshal(stores)
// 	return data
// }

// func GetCurrentStore() string {
// 	x := db.Get([]byte("CURRENT"))
// 	if len(x) == 0 {
// 		return "Default"
// 	}

// 	return string(x)
// }

var (
	AllowLanKey     = "allow_lan"
	AppendHTTPProxy = "Append HTTP Proxy to VPN"
	IPv6Key         = "ipv6"
	AutoConnectKey  = "auto_connect"
	PerAppKey       = "per_app"
	AppBypassKey    = "app_bypass"
	UDPProxyFQDNKey = "UDP proxy FQDN"
	SniffKey        = "Sniff"
	SaveLogcatKey   = "save_logcat"

	RouteKey         = "route"
	FakeDNSCIDRKey   = "fake_dns_cidr"
	FakeDNSv6CIDRKey = "fake_dnsv6_cidr"
	TunDriverKey     = "Tun Driver"
	AppListKey       = "app_list"
	LogLevelKey      = "Log Level"
	RuleByPassUrlKey = "Rule Update Bypass"
	BlockKey         = "Block"
	ProxyKey         = "Proxy"
	DirectKey        = "Direct"
	TCPBypassKey     = "TCP"
	UDPBypassKey     = "UDP"
	HostsKey         = "hosts"

	DNSPortKey     = "dns_port"
	HTTPPortKey    = "http_port"
	YuhaiinPortKey = "yuhaiin_port"

	DNSHijackingKey = "dns_hijacking"

	RemoteDNSHostKey          = "remote_dns_host"
	RemoteDNSTypeKey          = "remote_dns_type"
	RemoteDNSSubnetKey        = "remote_dns_subnet"
	RemoteDNSTLSServerNameKey = "remote_dns_tls_server_name"
	RemoteDNSResolveDomainKey = "remote_dns_resolve_domain"

	LocalDNSHostKey          = "local_dns_host"
	LocalDNSTypeKey          = "local_dns_type"
	LocalDNSSubnetKey        = "local_dns_subnet"
	LocalDNSTLSServerNameKey = "local_dns_tls_server_name"

	BootstrapDNSHostKey          = "bootstrap_dns_host"
	BootstrapDNSTypeKey          = "bootstrap_dns_type"
	BootstrapDNSSubnetKey        = "bootstrap_dns_subnet"
	BootstrapDNSTLSServerNameKey = "bootstrap_dns_tls_server_name"
)

var (
	defaultBoolValue = map[string]byte{
		AllowLanKey:               0,
		AppendHTTPProxy:           0,
		IPv6Key:                   1,
		AutoConnectKey:            0,
		PerAppKey:                 0,
		AppBypassKey:              0,
		UDPProxyFQDNKey:           0,
		SniffKey:                  1,
		DNSHijackingKey:           1,
		RemoteDNSResolveDomainKey: 0,
		SaveLogcatKey:             0,
	}

	defaultStringValue = map[string]string{
		RouteKey:         "All (Default)",
		FakeDNSCIDRKey:   "10.0.2.1/16",
		FakeDNSv6CIDRKey: "fc00::/64",
		TunDriverKey:     "system_gvisor",
		AppListKey:       `["io.github.yuhaiin"]`,
		LogLevelKey:      "info",

		RuleByPassUrlKey: "https://raw.githubusercontent.com/yuhaiin/kitte/main/yuhaiin/remote.conf",
		// rules
		BlockKey:  "",
		ProxyKey:  "",
		DirectKey: "",

		TCPBypassKey: "bypass",
		UDPBypassKey: "bypass",

		HostsKey: `{"example.com": "127.0.0.1"}`,

		RemoteDNSHostKey:          "cloudflare.com",
		RemoteDNSTypeKey:          "doh",
		RemoteDNSSubnetKey:        "",
		RemoteDNSTLSServerNameKey: "",

		LocalDNSHostKey:          "1.1.1.1",
		LocalDNSTypeKey:          "doh",
		LocalDNSSubnetKey:        "",
		LocalDNSTLSServerNameKey: "",

		BootstrapDNSHostKey:          "1.1.1.1",
		BootstrapDNSTypeKey:          "doh",
		BootstrapDNSSubnetKey:        "",
		BootstrapDNSTLSServerNameKey: "",
	}

	defaultIntValue = map[string]int32{
		DNSPortKey:     0,
		HTTPPortKey:    0,
		YuhaiinPortKey: 3500,
	}

	defaultLangValue  = map[string]int64{}
	defaultFloatValue = map[string]float32{}
)

type MapStore struct {
	store map[string][]byte
}

func MapStoreFromJson(data []byte) *MapStore {
	log.Info("[MapStoreFromJson]", "data", string(data))

	store := &MapStore{store: map[string][]byte{}}

	err := json.Unmarshal(data, &store.store)
	if err != nil {
		log.Error("[MapStoreFromJson]", "err", err)
	}
	return store
}

func (m *MapStore) GetString(key string) string {
	x, ok := m.store[key]
	if !ok {
		return defaultStringValue[key]
	}

	return string(x)
}

func (m *MapStore) GetInt(key string) int32 {
	x, ok := m.store[key]
	if !ok {
		return defaultIntValue[key]
	}

	return int32(binary.NativeEndian.Uint32(x))
}

func (m *MapStore) GetBoolean(key string) bool {
	x, ok := m.store[key]
	if !ok {
		return defaultBoolValue[key] == 1
	}

	return x[0] == 1
}

func (m *MapStore) GetFloat(key string) float32 {
	x, ok := m.store[key]
	if !ok {
		return defaultFloatValue[key]
	}

	return math.Float32frombits(binary.NativeEndian.Uint32(x))
}

func (m *MapStore) GetLong(key string) int64 {
	x, ok := m.store[key]
	if !ok {
		return defaultLangValue[key]
	}

	return int64(binary.NativeEndian.Uint64(x))
}
