package netapi

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
)

type ContextResolver struct {
	Resolver     Resolver
	ResolverSelf Resolver
	PreferIPv6   bool
	PreferIPv4   bool
	SkipResolve  bool `metrics:"-"`
	ForceFakeIP  bool `metrics:"-"`
}

type Context struct {
	Resolver ContextResolver `metrics:"-"`

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

	ForceMode bypass.Mode `metrics:"-"`
	Mode      bypass.Mode `metrics:"MODE"`

	UDPMigrateID uint64 `metrics:"UDP MigrateID"`
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
