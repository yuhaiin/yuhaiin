package netapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
)

type ResolverMode int

const (
	ResolverModeNoSpecified ResolverMode = iota
	ResolverModePreferIPv6
	ResolverModePreferIPv4
)

type ContextResolver struct {
	Resolver     Resolver
	ResolverSelf Resolver
	Mode         ResolverMode
	SkipResolve  bool `metrics:"-"`
	ForceFakeIP  bool `metrics:"-"`
}

func (r ContextResolver) Opts(reverse bool) []func(*LookupIPOption) {
	switch r.Mode {
	case ResolverModePreferIPv6, ResolverModePreferIPv4:
		return []func(*LookupIPOption){func(li *LookupIPOption) {
			if r.Mode == ResolverModePreferIPv4 || reverse {
				li.Mode = ResolverModePreferIPv4
			} else {
				li.Mode = ResolverModePreferIPv6
			}
		}}
	}

	return nil
}

type Context struct {
	Source      net.Addr `metrics:"Source"`
	Inbound     net.Addr `metrics:"Inbound"`
	Destination net.Addr `metrics:"Destination"`
	FakeIP      net.Addr `metrics:"FakeIP"`
	Hosts       net.Addr `metrics:"Hosts"`

	context.Context

	DomainString string `metrics:"DOMAIN"`
	IPString     string `metrics:"IP"`
	Tag          string `metrics:"Tag"`
	Hash         string `metrics:"Hash"`

	// sniffy
	Protocol      string `metrics:"Protocol"`
	Process       string `metrics:"Process"`
	TLSServerName string `metrics:"TLS Servername"`
	HTTPHost      string `metrics:"HTTP Host"`

	// dns resolver
	Component string `metrics:"Component"`

	Resolver ContextResolver `metrics:"-"`

	UDPMigrateID uint64 `metrics:"UDP MigrateID"`

	ForceMode  bypass.Mode `metrics:"-"`
	SniffMode  bypass.Mode `metrics:"-"`
	Mode       bypass.Mode `metrics:"MODE"`
	ModeReason string      `metrics:"MODE Reason"`
	SkipRoute  bool        `metrics:"-"`
}

func (addr *Context) Map() map[string]string {
	values := reflect.ValueOf(*addr)
	types := reflect.TypeOf(*addr)

	maps := make(map[string]string)

	for i := range values.NumField() {
		v, ok := toString(values.Field(i))
		if !ok || v == "" {
			continue
		}

		k := types.Field(i).Tag.Get("metrics")
		if k == "" || k == "-" {
			continue
		}

		maps[k] = v
	}

	return maps
}

func toString(t reflect.Value) (string, bool) {
	if !t.IsValid() {
		return "", false
	}

	switch t.Kind() {
	case reflect.String:
		return t.String(), true
	default:
		if t.CanInterface() {
			if z, ok := t.Interface().(fmt.Stringer); ok {
				return z.String(), true
			}
		}
	}

	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		integer := t.Int()
		if integer != 0 {
			return strconv.FormatInt(t.Int(), 10), true
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		uinteger := t.Uint()
		if uinteger != 0 {
			return strconv.FormatUint(t.Uint(), 10), true
		}
	}

	return "", false
}

func (c *Context) SniffHost() string {
	if c.TLSServerName != "" {
		return c.TLSServerName
	}

	return c.HTTPHost
}

func (c *Context) Value(key any) any {
	switch key {
	case contextKey{}:
		return c
	default:
		return c.Context.Value(key)
	}
}

type contextKey struct{}

func WithContext(ctx context.Context) *Context {
	return &Context{
		Context: ctx,
	}
}

func GetContext(ctx context.Context) *Context {
	v, ok := ctx.Value(contextKey{}).(*Context)
	if !ok {
		return &Context{
			Context: ctx,
		}
	}

	return v
}

func NewDialError(network string, err error, addr net.Addr) *DialError {
	ne := &DialError{}
	if errors.As(err, &ne) {
		return ne
	}

	return &DialError{
		Op:   "dial",
		Net:  network,
		Err:  err,
		Addr: addr,
	}
}

// OpError is the error type usually returned by functions in the net
// package. It describes the operation, network type, and address of
// an error.
type DialError struct {
	// Op is the operation which caused the error, such as
	// "read" or "write".
	Op string

	// Net is the network type on which this error occurred,
	// such as "tcp" or "udp6".
	Net string

	Sniff string

	// Addr is the network address for which this error occurred.
	// For local operations, like Listen or SetDeadline, Addr is
	// the address of the local endpoint being manipulated.
	// For operations involving a remote network connection, like
	// Dial, Read, or Write, Addr is the remote address of that
	// connection.
	Addr net.Addr

	// Err is the error that occurred during the operation.
	// The Error method panics if the error is nil.
	Err error
}

func (e *DialError) Unwrap() error { return e.Err }

func (e *DialError) Error() string {
	if e == nil {
		return "<nil>"
	}
	s := e.Op
	if e.Sniff != "" {
		s += " [sniffed " + e.Sniff + "]"
	}
	if e.Net != "" {
		s += " " + e.Net
	}
	if e.Addr != nil {
		s += " "
		s += e.Addr.String()
	}
	s += ": " + e.Err.Error()
	return s
}
