package accesscontrol

import (
	"context"
	"errors"
	"net"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/route"
)

type accessRouteResolver struct{ netapi.Resolver }

func (accessRouteResolver) LookupIP(context.Context, string, ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	return &netapi.IPs{A: []net.IP{net.IPv4(192, 0, 2, 8)}}, nil
}
func (r accessRouteResolver) Get(string, string) netapi.Resolver { return r }

type accessRouteDialer struct{ calls int }

func (d *accessRouteDialer) GetTarget(context.Context, string, string, contract.Target) (netapi.Proxy, error) {
	d.calls++
	return netapi.NewErrProxy(errors.New("dial must not run")), nil
}

func TestRouteOverridesFallbackSkipAndFakeIPCannotBypassAccess(t *testing.T) {
	c := New()
	defer c.Close()
	install(t, c, config())
	dialer := new(accessRouteDialer)
	lists := route.NewLists(nil, nil, t.TempDir())
	defer lists.Close()
	router := route.NewRoute(dialer, accessRouteResolver{}, lists, nil)
	router.SetTrafficAccess(c)
	ctx := netapi.WithContext(netapi.WithTrafficIdentity(t.Context(), subject(t.Context(), "alice").Identity))
	ctx.SetInboundID("entry")
	dst := address(t, "tcp", "192.0.2.8:443")
	for _, mode := range []string{"", "direct", "proxy"} {
		ctx.ConnOptions().SetRouteMode(mode)
		for _, target := range []contract.Target{{Type: "inherit_route"}, {Type: "direct"}, {Type: "default"}, {Type: "node", ID: "chosen"}} {
			if _, _, err := router.ResolveTCP(ctx, dst, target); !errors.Is(err, netapi.ErrTrafficAccessDenied) {
				t.Fatalf("mode=%s target=%+v bypass: %v", mode, target, err)
			}
		}
	}
	ctx.ConnOptions().SetSkipRoute(true)
	if _, err := router.Dispatch(ctx, dst); !errors.Is(err, netapi.ErrTrafficAccessDenied) {
		t.Fatal("SkipRoute bypass", err)
	}
	ctx.ConnOptions().MarkUnmappedFakeIP()
	if _, err := router.Dispatch(ctx, dst); err == nil {
		t.Fatal("unmapped FakeIP bypass")
	}
	udp := address(t, "udp", "192.0.2.8:443")
	if _, err := router.PacketConn(ctx, udp); !errors.Is(err, netapi.ErrTrafficAccessDenied) {
		t.Fatal("untracked external packet socket", err)
	}
	if _, err := router.Ping(ctx, udp); !errors.Is(err, netapi.ErrTrafficAccessDenied) {
		t.Fatal("unsupported protected ping", err)
	}
}

type rejectingInheritedSession struct{ calls int }

func (s *rejectingInheritedSession) Authorize(netapi.Address, net.Addr) error {
	s.calls++
	return netapi.ErrTrafficAccessDenied
}
func (*rejectingInheritedSession) Close() {}

func TestResolverInfrastructureDoesNotUseInheritedClientAuthorization(t *testing.T) {
	c := New()
	defer c.Close()
	install(t, c, config())
	lists := route.NewLists(nil, nil, t.TempDir())
	defer lists.Close()
	router := route.NewRoute(new(accessRouteDialer), accessRouteResolver{}, lists, nil)
	router.SetTrafficAccess(c)
	parent := netapi.WithContext(netapi.WithTrafficIdentity(t.Context(), subject(t.Context(), "alice").Identity))
	parent.SetInboundID("entry")
	session := new(rejectingInheritedSession)
	infrastructure := netapi.WithContext(netapi.WithTrafficAuthorization(parent, session, t.Context()))
	infrastructure.ConnOptions().SetSkipRoute(true)
	if _, err := router.Dispatch(infrastructure, address(t, "udp", "192.0.2.53:53")); err != nil {
		t.Fatal("resolver infrastructure charged against client policy", err)
	}
	if session.calls != 0 {
		t.Fatal("inherited client authorization used by infrastructure")
	}
}
