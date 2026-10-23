package netapi_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/access"
	rule "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/accesscontrol"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
)

func accessContext(t *testing.T) *netapi.Context {
	t.Helper()
	ctx := netapi.WithContext(netapi.WithTrafficIdentity(t.Context(), &proxyauth.Identity{UserID: "alice", CredentialID: "phone", Context: t.Context()}))
	ctx.SetInboundID("entry")
	return ctx
}
func accessAction(t *testing.T, c *accesscontrol.Controller, action string) {
	t.Helper()
	p, err := accesscontrol.Prepare(contract.Config{Enabled: true, Scope: contract.Scope{AllInbounds: true}, DefaultAction: action})
	if err != nil {
		t.Fatal(err)
	}
	c.Activate(p)
}
func TestDialTrafficRevokesEstablishedAndPendingDials(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "established", true: "pending"}[pending], func(t *testing.T) {
			c := accesscontrol.New()
			defer c.Close()
			accessAction(t, c, "allow")
			ctx := accessContext(t)
			dst := netapi.ParseIPAddr("tcp", net.IPv4(192, 0, 2, 8), 443)
			local, remote := net.Pipe()
			defer remote.Close()
			started := make(chan struct{})
			done := make(chan error, 1)
			if pending {
				go func() {
					conn, err := netapi.DialTraffic(ctx, c, dst, dst, func(ctx context.Context, _ netapi.Address) (net.Conn, error) {
						close(started)
						<-ctx.Done()
						return local, nil
					})
					if conn != nil {
						_ = conn.Close()
					}
					done <- err
				}()
				<-started
				accessAction(t, c, "deny")
				select {
				case err := <-done:
					if !errors.Is(err, netapi.ErrTrafficAccessDenied) {
						t.Fatal("pending result escaped", err)
					}
				case <-time.After(time.Second):
					t.Fatal("pending dial not cancelled")
				}
			} else {
				conn, err := netapi.DialTraffic(ctx, c, dst, dst, func(context.Context, netapi.Address) (net.Conn, error) { return local, nil })
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				go func() { _, err := conn.Read(make([]byte, 1)); done <- err }()
				accessAction(t, c, "deny")
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("revoked read succeeded")
					}
				case <-time.After(time.Second):
					t.Fatal("established read not interrupted")
				}
			}
			if c.Status().Sessions != 0 {
				t.Fatal("authorization leaked")
			}
			if !errors.Is(context.Cause(netapi.TrafficAuthorizationContext(ctx)), netapi.ErrTrafficAccessDenied) {
				t.Fatal("missing policy revocation cause")
			}
		})
	}
}

type accessResolver struct {
	netapi.Resolver
	ips   *netapi.IPs
	calls int
}

func (r *accessResolver) LookupIP(context.Context, string, ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	r.calls++
	return r.ips, nil
}
func TestPinTrafficTargetRejectsRebindingAndReturnsOnlyAuthorizedIP(t *testing.T) {
	c := accesscontrol.New()
	defer c.Close()
	p, err := accesscontrol.Prepare(contract.Config{Enabled: true, Scope: contract.Scope{AllInbounds: true}, DefaultAction: "deny", Rules: []contract.Rule{
		{ID: "private", Action: "deny", Conditions: []rule.RuleExpr{{Type: "destination", Destination: &rule.DestinationExpr{CIDRs: []string{"10.0.0.0/8"}}}}},
		{ID: "domain", Action: "allow", Conditions: []rule.RuleExpr{{Type: "destination", Destination: &rule.DestinationExpr{Domains: []string{"service.example"}}}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	c.Activate(p)
	ctx := accessContext(t)
	resolver := &accessResolver{ips: &netapi.IPs{A: []net.IP{net.IPv4(10, 1, 2, 3), net.IPv4(192, 0, 2, 8)}}}
	ctx.ConnOptions().Resolver().SetResolver(resolver)
	domain, _ := netapi.ParseAddress("tcp", "service.example:443")
	actual, err := netapi.PinTrafficDestination(ctx, c, domain)
	if err != nil || actual.IsFqdn() || actual.Hostname() != "192.0.2.8" || resolver.calls != 1 {
		t.Fatal("not pinned", actual, err, resolver.calls)
	}
	resolver.ips = &netapi.IPs{A: []net.IP{net.IPv4(10, 1, 2, 3)}}
	if _, err := netapi.PinTrafficDestination(ctx, c, domain); !errors.Is(err, netapi.ErrTrafficAccessDenied) {
		t.Fatal("DNS rebinding allowed", err)
	}
	anonymous := netapi.WithContext(t.Context())
	anonymous.SetInboundID("entry")
	anonymous.ConnOptions().Resolver().SetResolver(resolver)
	before := resolver.calls
	if _, err := netapi.PinTrafficDestination(anonymous, c, domain); !errors.Is(err, netapi.ErrTrafficAccessDenied) || resolver.calls != before {
		t.Fatal("anonymous request reached DNS", err)
	}
}

type slowClosingAccessConn struct {
	net.Conn
	release <-chan struct{}
}

func (c slowClosingAccessConn) Close() error { <-c.release; return c.Conn.Close() }

func TestRevocationInterruptsIOBeforeSlowGracefulCloseFinishes(t *testing.T) {
	c := accesscontrol.New()
	defer c.Close()
	accessAction(t, c, "allow")
	release := make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	defer releaseOnce()
	dst := netapi.ParseIPAddr("tcp", net.IPv4(192, 0, 2, 8), 443)
	reads := make(chan error, 2)
	for range 2 {
		local, remote := net.Pipe()
		defer remote.Close()
		conn, err := netapi.DialTraffic(accessContext(t), c, dst, dst, func(context.Context, netapi.Address) (net.Conn, error) {
			return slowClosingAccessConn{Conn: local, release: release}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		go func() { _, err := conn.Read(make([]byte, 1)); reads <- err }()
	}
	deny, err := accesscontrol.Prepare(contract.Config{Enabled: true, Scope: contract.Scope{AllInbounds: true}, DefaultAction: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); c.Activate(deny) }()
	defer func() { releaseOnce(); <-done }()
	for range 2 {
		select {
		case err := <-reads:
			if err == nil {
				t.Fatal("revoked I/O succeeded")
			}
		case <-time.After(time.Second):
			t.Fatal("slow close delayed another connection's I/O cancellation")
		}
	}
	select {
	case <-done:
		t.Fatal("transport teardown was not joined")
	default:
	}
}
