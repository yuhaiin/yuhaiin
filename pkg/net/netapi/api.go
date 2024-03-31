package netapi

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

type ProcessDumper interface {
	ProcessName(network string, src, dst Address) (string, error)
}

type Proxy interface {
	StreamProxy
	PacketProxy
	Dispatch(context.Context, Address) (Address, error)
}

type StreamProxy interface {
	Conn(context.Context, Address) (net.Conn, error)
}

type PacketProxy interface {
	PacketConn(context.Context, Address) (net.PacketConn, error)
}

type Port interface {
	Port() uint16
	String() string
}

type Type uint8

func (t Type) String() string {
	switch t {
	case FQDN:
		return "FQDN"
	case IP:
		return "IP"
	case UNIX:
		return "UNIX"
	case EMPTY:
		return "EMPTY"
	default:
		return "UNKNOWN"
	}
}

const (
	FQDN  Type = 1
	IP    Type = 2
	UNIX  Type = 3
	EMPTY Type = 4
)

type AddressSrc int32

const (
	AddressSrcEmpty AddressSrc = 0
	AddressSrcDNS   AddressSrc = 1
)

type Result[T any] struct {
	V   T
	Err error
}

func NewErrResult[T any](err error) Result[T] {
	return Result[T]{Err: err}
}

func NewResult[T any](v T) Result[T] {
	return Result[T]{V: v}
}

type Address interface {
	// Hostname return hostname of address, eg: www.example.com, 127.0.0.1, ff::ff
	Hostname() string
	IPs(context.Context) ([]net.IP, error)
	// IP return net.IP, if address is ip else resolve the domain and return one of ips
	IP(context.Context) (net.IP, error)
	AddrPort(context.Context) Result[netip.AddrPort]
	UDPAddr(context.Context) Result[*net.UDPAddr]
	TCPAddr(context.Context) Result[*net.TCPAddr]
	// Port return port of address
	Port() Port
	// Type return type of address, domain or ip
	Type() Type
	NetworkType() statistic.Type

	net.Addr

	SetSrc(AddressSrc)
	// SetResolver will use call IP(), IPHost(), UDPAddr(), TCPAddr()
	SetResolver(_ Resolver)
	PreferIPv6(b bool)
	PreferIPv4(b bool)
	// OverrideHostname clone address(exclude Values) and change hostname
	OverrideHostname(string) Address
	OverridePort(Port) Address

	IsFqdn() bool
}

type Store interface {
	Add(k, v any) Store
	Get(k any) (any, bool)
	Range(func(k, v any) bool)
	Map() map[any]any
}

type storeKey struct{}

func StoreFromContext(ctx context.Context) Store {
	store, ok := ctx.Value(storeKey{}).(Store)
	if !ok {
		return EmptyStore
	}

	return store
}

func NewStore(ctx context.Context) context.Context {
	// ! it must return new context with store
	// ! otherwise dns across proxy will use same store with proxy
	return context.WithValue(ctx, storeKey{}, &store{store: make(map[any]any)})
}

func Get[T any](ctx context.Context, k any) (t T, _ bool) {
	v, ok := StoreFromContext(ctx).Get(k)
	if !ok {
		return t, false
	}

	t, ok = v.(T)

	return t, ok
}

func GetDefault[T any](ctx context.Context, k any, Default T) T {
	v, ok := StoreFromContext(ctx).Get(k)
	if !ok {
		return Default
	}

	t, ok := v.(T)
	if !ok {
		return Default
	}

	return t
}

var EmptyStore = &emptyStore{}

type emptyStore struct{}

func (e *emptyStore) Add(k, v any) Store      { return e }
func (*emptyStore) Get(k any) (any, bool)     { return nil, false }
func (*emptyStore) Range(func(k, v any) bool) {}
func (s *emptyStore) Map() map[any]any        { return map[any]any{} }

type store struct {
	mu    sync.RWMutex
	store map[any]any
}

func (s *store) Add(key, value any) Store {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store == nil {
		s.store = make(map[any]any)
	}

	s.store[key] = value

	return s
}

func (s *store) Map() map[any]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.store == nil {
		return map[any]any{}
	}
	return s.store
}

func (s *store) Get(key any) (any, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.store == nil {
		return nil, false
	}
	v, ok := s.store[key]
	return v, ok
}

func (s *store) Range(f func(k, v any) bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for k, v := range s.store {
		if !f(k, v) {
			break
		}
	}
}
