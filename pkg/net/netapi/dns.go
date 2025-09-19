package netapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"iter"
	"math/rand/v2"
	"net"
	"time"

	"github.com/miekg/dns"
)

type LookupIPOption struct {
	Mode ResolverMode
}

type IPs struct {
	AAAA []net.IP
	A    []net.IP
}

func (i *IPs) WhoNotEmpty() []net.IP {
	if len(i.AAAA) != 0 {
		return i.AAAA
	}
	return i.A
}

func (i *IPs) PreferAAAA() net.IP {
	if len(i.AAAA) != 0 {
		return i.AAAA[0]
	}

	return i.A[0]
}

func (i *IPs) PreferA() net.IP {
	if len(i.A) != 0 {
		return i.A[0]
	}

	return i.AAAA[0]
}

func (i *IPs) Rand() net.IP {
	if len(i.A) != 0 && len(i.AAAA) != 0 {
		if rand.IntN(2) == 0 {
			return i.A[rand.IntN(len(i.A))]
		}
		return i.AAAA[rand.IntN(len(i.AAAA))]
	}

	if len(i.A) != 0 {
		return i.A[rand.IntN(len(i.A))]
	}

	if len(i.AAAA) != 0 {
		return i.AAAA[rand.IntN(len(i.AAAA))]
	}

	return nil
}

func (i *IPs) Len() int {
	return len(i.A) + len(i.AAAA)
}

func (i *IPs) Iter() iter.Seq[net.IP] {
	return func(yield func(net.IP) bool) {
		for _, v := range i.A {
			if !yield(v) {
				return
			}
		}

		for _, v := range i.AAAA {
			if !yield(v) {
				return
			}
		}
	}
}

// Resolver is a dns resolver
//
// TODO merge LookupIP and Raw, new interface for Resolver
type Resolver interface {
	// LookupIP returns a list of ip addresses
	LookupIP(ctx context.Context, domain string, opts ...func(*LookupIPOption)) (*IPs, error)
	// Raw returns a dns message
	Raw(ctx context.Context, req dns.Question) (dns.Msg, error)
	io.Closer
}

var _ Resolver = (*ErrorResolver)(nil)

type ErrorResolver func(domain string) error

func (e ErrorResolver) LookupIP(_ context.Context, domain string, opts ...func(*LookupIPOption)) (*IPs, error) {
	return &IPs{}, e(domain)
}
func (e ErrorResolver) Close() error { return nil }
func (e ErrorResolver) Raw(_ context.Context, req dns.Question) (dns.Msg, error) {
	return dns.Msg{
		MsgHdr: dns.MsgHdr{
			Response:           true,
			Opcode:             dns.OpcodeQuery,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   true,
			RecursionAvailable: true,
			Rcode:              dns.RcodeSuccess,
		},
		Question: []dns.Question{req},
	}, nil
}

// dnsConn is a net.PacketConn suitable for returning from
// net.Dialer.Dial to send DNS queries over Bootstrap.
type dnsConn struct {
	ctx      context.Context
	resolver Resolver
	rbuf     bytes.Buffer
}

func NewDnsConn(ctx context.Context, resolver Resolver) *dnsConn {
	return &dnsConn{ctx: ctx, resolver: resolver}
}

var (
	_ net.Conn       = (*dnsConn)(nil)
	_ net.PacketConn = (*dnsConn)(nil) // be a PacketConn to change net.Resolver semantics
)

func (*dnsConn) Close() error                       { return nil }
func (*dnsConn) LocalAddr() net.Addr                { return todoAddr{} }
func (*dnsConn) RemoteAddr() net.Addr               { return todoAddr{} }
func (*dnsConn) SetDeadline(t time.Time) error      { return nil }
func (*dnsConn) SetReadDeadline(t time.Time) error  { return nil }
func (*dnsConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *dnsConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.Write(p)
}

func (c *dnsConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.Read(p)
	return n, todoAddr{}, err
}

func (c *dnsConn) Read(p []byte) (n int, err error) {
	return c.rbuf.Read(p)
}

func (c *dnsConn) Write(packet []byte) (n int, err error) {
	var rmsg dns.Msg

	if err = rmsg.Unpack(packet); err != nil {
		return 0, err
	}

	if len(rmsg.Question) == 0 {
		return 0, errors.New("no question")
	}

	// log.Info("tailscale dns query", "name", rmsg.Questions[0].Name, "type", rmsg.Questions[0].Type)

	ctx, cancel := context.WithTimeout(c.ctx, time.Second*20)
	defer cancel()
	msg, err := c.resolver.Raw(ctx, rmsg.Question[0])
	if err != nil {
		return 0, err
	}

	data, err := msg.Pack()
	if err != nil {
		return 0, err
	}

	c.rbuf.Reset()
	c.rbuf.Write(data)

	return len(packet), nil
}

type todoAddr struct{}

func (todoAddr) Network() string { return "unused" }
func (todoAddr) String() string  { return "unused-todoAddr" }
