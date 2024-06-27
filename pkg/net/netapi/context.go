package netapi

import (
	"context"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
)

type ContextResolver struct {
	PreferIPv6   bool
	PreferIPv4   bool
	SkipResolve  bool `metrics:"-"`
	ForceFakeIP  bool `metrics:"-"`
	Resolver     Resolver
	ResolverSelf Resolver
}

type Context struct {
	Resolver  ContextResolver `metrics:"-"`
	ForceMode bypass.Mode     `metrics:"-"`
	Mode      bypass.Mode     `metrics:"MODE"`

	Source      net.Addr `metrics:"Source"`
	Inbound     net.Addr `metrics:"Inbound"`
	Destination net.Addr `metrics:"Destination"`
	FakeIP      net.Addr `metrics:"FakeIP"`
	Hosts       net.Addr `metrics:"Hosts"`
	Current     net.Addr `metrics:"Current"`

	DomainString string `metrics:"DOMAIN"`
	IPString     string `metrics:"IP"`
	Tag          string `metrics:"Tag"`
	Hash         string `metrics:"Hash"`

	// sniffy
	Protocol string `metrics:"Protocol"`
	Process  string `metrics:"Process"`

	// dns resolver
	Component string `metrics:"Component"`

	context.Context
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
