package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/semaphore"
)

func TestDial(t *testing.T) {
	t.Run("all resolve failed", func(t *testing.T) {
		ctx := netapi.WithContext(t.Context())
		ctx.ConnOptions().Resolver().SetResolver(&mockResolver{err: errors.New("mock DNS failure")})

		addr, err := netapi.ParseDomainPort("tcp", "happy-eyeballs.test", 46267)
		assert.NoError(t, err)
		_, err = DialHappyEyeballsv2(ctx, addr)
		t.Log(err)
		assert.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		server := newLocalHappyEyeballsServer(t)
		ctx := netapi.WithContext(t.Context())
		ctx.ConnOptions().Resolver().SetResolver(&mockResolver{ips: server.ips})

		addr, err := netapi.ParseDomainPort("tcp", "happy-eyeballs.test", server.port)
		assert.NoError(t, err)
		conn, err := DialHappyEyeballsv2(ctx, addr)
		assert.NoError(t, err)

		defer conn.Close()
	})

	t.Run("prefer all resolve failed", func(t *testing.T) {
		ctx := netapi.WithContext(t.Context())

		ctx.ConnOptions().Resolver().SetMode(netapi.ResolverModePreferIPv4)
		ctx.ConnOptions().Resolver().SetResolver(&mockResolver{err: errors.New("mock DNS failure")})

		addr, err := netapi.ParseDomainPort("tcp", "happy-eyeballs.test", 46267)
		assert.NoError(t, err)
		_, err = DialHappyEyeballsv2(ctx, addr)
		t.Log(err)
		assert.Error(t, err)
	})

	t.Run("prefer ipv4", func(t *testing.T) {
		server := newLocalHappyEyeballsServer(t)
		ctx := netapi.WithContext(t.Context())

		ctx.ConnOptions().Resolver().SetMode(netapi.ResolverModePreferIPv4)
		ctx.ConnOptions().Resolver().SetResolver(&mockResolver{ips: server.ips})

		addr, err := netapi.ParseDomainPort("tcp", "happy-eyeballs.test", server.port)
		assert.NoError(t, err)
		conn, err := DialHappyEyeballsv2(ctx, addr)
		assert.NoError(t, err)

		defer conn.Close()
		assertDialedFamily(t, conn, false)
	})

	t.Run("prefer ipv6", func(t *testing.T) {
		server := newLocalHappyEyeballsServer(t)
		if len(server.ips.AAAA) == 0 {
			t.Skip("IPv6 loopback is unavailable")
		}

		ctx := netapi.WithContext(t.Context())

		ctx.ConnOptions().Resolver().SetMode(netapi.ResolverModePreferIPv6)
		ctx.ConnOptions().Resolver().SetResolver(&mockResolver{ips: server.ips})

		addr, err := netapi.ParseDomainPort("tcp", "happy-eyeballs.test", server.port)
		assert.NoError(t, err)
		conn, err := DialHappyEyeballsv2(ctx, addr)
		assert.NoError(t, err)

		defer conn.Close()
		assertDialedFamily(t, conn, true)
	})
}

type localHappyEyeballsServer struct {
	port uint16
	ips  netapi.IPs
}

func newLocalHappyEyeballsServer(t *testing.T) localHappyEyeballsServer {
	t.Helper()

	ipv4, err := net.Listen("tcp4", "127.0.0.1:0")
	assert.NoError(t, err)
	acceptAndClose(t, ipv4)

	port := uint16(ipv4.Addr().(*net.TCPAddr).Port)
	server := localHappyEyeballsServer{
		port: port,
		ips:  netapi.IPs{A: []net.IP{net.IPv4(127, 0, 0, 1)}},
	}

	ipv6, err := net.Listen("tcp6", net.JoinHostPort("::1", fmt.Sprint(port)))
	if err != nil {
		t.Logf("IPv6 loopback unavailable: %v", err)
		return server
	}
	acceptAndClose(t, ipv6)
	server.ips.AAAA = []net.IP{net.ParseIP("::1")}

	return server
}

func acceptAndClose(t *testing.T, listener net.Listener) {
	t.Helper()
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
}

func assertDialedFamily(t *testing.T, conn net.Conn, wantIPv6 bool) {
	t.Helper()

	addr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("RemoteAddr() = %T, want *net.TCPAddr", conn.RemoteAddr())
	}
	gotIPv6 := addr.IP.To4() == nil
	if gotIPv6 != wantIPv6 {
		t.Fatalf("connected to %s, want IPv6=%t", addr, wantIPv6)
	}
}

func TestResolver(t *testing.T) {
	ad, err := netapi.ParseAddress("tcp", "happy-eyeballs.test")
	assert.NoError(t, err)

	ctx := netapi.WithContext(t.Context())

	ctx.ConnOptions().Resolver().SetResolver(&mockResolver{ips: netapi.IPs{
		AAAA: []net.IP{net.ParseIP("::1")},
		A:    []net.IP{net.IPv4(127, 0, 0, 1)},
	}})

	r := newHappyEyeballv2Respover(ctx, ad, happyEyeballsCache, semaphore.NewEmptySemaphore())

	for {
		p, err := r.wait()
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				assert.NoError(t, err)
			}
			break
		}

		t.Log(p)
	}

	t.Log(r.errors)
}

type mockResolver struct {
	ips netapi.IPs
	err error
}

// LookupIP returns a list of ip addresses
func (m *mockResolver) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	if m.err != nil {
		return nil, m.err
	}

	var option netapi.LookupIPOption
	for _, opt := range opts {
		opt(&option)
	}

	switch option.Mode {
	case netapi.ResolverModePreferIPv4:
		return &netapi.IPs{A: m.ips.A}, nil
	case netapi.ResolverModePreferIPv6:
		return &netapi.IPs{AAAA: m.ips.AAAA}, nil
	}

	return &m.ips, nil
}

// Raw returns a dns message
func (m *mockResolver) Raw(ctx context.Context, req netapi.DNSQuestion) (*dns.Msg, error) {
	return nil, errors.ErrUnsupported
}

func (m *mockResolver) Close() error {
	return nil
}

func (m *mockResolver) Name() string {
	return "mock"
}

func TestError(t *testing.T) {
	x := &net.OpError{
		Op:   "block",
		Net:  "tcp",
		Addr: netapi.EmptyAddr,
		Err:  net.UnknownNetworkError("unknown network"),
	}

	y := fmt.Errorf("x: %w", x)

	assert.Equal(t, netapi.IsBlockError(y), true)
}
