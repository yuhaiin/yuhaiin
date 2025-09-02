package dialer

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/miekg/dns"
)

func TestDial(t *testing.T) {

	t.Run("all resolve failed", func(t *testing.T) {
		addr, err := netapi.ParseDomainPort("tcp", "ip-3-86-108-113-ext.gold0028.gameloft.com", 46267)
		assert.NoError(t, err)
		_, err = DialHappyEyeballsv2(context.TODO(), addr)
		assert.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		ctx := netapi.WithContext(t.Context())

		ctx.Resolver.Resolver = &mockResolver{}

		addr, err := netapi.ParseDomainPort("tcp", "ip-3-86-108-113-ext.gold0028.gameloft.com", 46267)
		assert.NoError(t, err)
		conn, err := DialHappyEyeballsv2(ctx, addr)
		assert.NoError(t, err)

		defer conn.Close()
	})

	t.Run("prefer all resolve failed", func(t *testing.T) {
		ctx := netapi.WithContext(t.Context())

		ctx.Resolver.Mode = netapi.ResolverModePreferIPv4

		addr, err := netapi.ParseDomainPort("tcp", "ip-3-86-108-113-ext.gold0028.gameloft.com", 46267)
		assert.NoError(t, err)
		_, err = DialHappyEyeballsv2(ctx, addr)
		assert.Error(t, err)
	})

	t.Run("prefer ipv4", func(t *testing.T) {
		ctx := netapi.WithContext(t.Context())

		ctx.Resolver.Mode = netapi.ResolverModePreferIPv4

		ctx.Resolver.Resolver = &mockResolver{}

		addr, err := netapi.ParseDomainPort("tcp", "ip-3-86-108-113-ext.gold0028.gameloft.com", 46267)
		assert.NoError(t, err)
		conn, err := DialHappyEyeballsv2(ctx, addr)
		assert.NoError(t, err)

		defer conn.Close()
	})

	t.Run("prefer ipv6", func(t *testing.T) {
		ctx := netapi.WithContext(t.Context())

		ctx.Resolver.Mode = netapi.ResolverModePreferIPv6

		ctx.Resolver.Resolver = &mockResolver{}

		addr, err := netapi.ParseDomainPort("tcp", "ip-3-86-108-113-ext.gold0028.gameloft.com", 46267)
		assert.NoError(t, err)
		conn, err := DialHappyEyeballsv2(ctx, addr)
		assert.NoError(t, err)

		defer conn.Close()
	})
}

func TestResolver(t *testing.T) {
	ad, err := netapi.ParseAddress("tcp", "www.google.com")
	assert.NoError(t, err)

	ctx := netapi.WithContext(t.Context())

	ctx.Resolver.Resolver = &mockResolver{}

	r := newHappyEyeballv2Respover(ctx, ad, happyEyeballsCache)

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

type mockResolver struct{}

// LookupIP returns a list of ip addresses
func (m *mockResolver) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	var option netapi.LookupIPOption
	for _, opt := range opts {
		opt(&option)
	}

	switch option.Mode {
	case netapi.ResolverModePreferIPv4:
		return &netapi.IPs{A: []net.IP{{10, 0, 0, 1}, {10, 0, 0, 2}}}, nil
	case netapi.ResolverModePreferIPv6:
		return &netapi.IPs{AAAA: []net.IP{net.ParseIP("::1"), net.ParseIP("::2")}}, nil
	}

	return &netapi.IPs{
		AAAA: []net.IP{net.ParseIP("::1"), net.ParseIP("::2")},
		A:    []net.IP{{10, 0, 0, 1}, {10, 0, 0, 2}},
	}, nil
}

// Raw returns a dns message
func (m *mockResolver) Raw(ctx context.Context, req dns.Question) (dns.Msg, error) {
	return dns.Msg{}, errors.ErrUnsupported
}

func (m *mockResolver) Close() error {
	return nil
}
