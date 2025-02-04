package netapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type LookupIPOption struct {
	Mode ResolverMode
}

type Resolver interface {
	LookupIP(ctx context.Context, domain string, opts ...func(*LookupIPOption)) ([]net.IP, error)
	Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error)
	io.Closer
}

var _ Resolver = (*ErrorResolver)(nil)

type ErrorResolver func(domain string) error

func (e ErrorResolver) LookupIP(_ context.Context, domain string, opts ...func(*LookupIPOption)) ([]net.IP, error) {
	return nil, e(domain)
}
func (e ErrorResolver) Close() error { return nil }
func (e ErrorResolver) Raw(_ context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	return dnsmessage.Message{}, e(req.Name.String())
}

// dnsConn is a net.PacketConn suitable for returning from
// net.Dialer.Dial to send DNS queries over Bootstrap.
type dnsConn struct {
	ctx      context.Context
	rbuf     bytes.Buffer
	resolver Resolver
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
	var rmsg dnsmessage.Message

	if err = rmsg.Unpack(packet); err != nil {
		return 0, err
	}

	if len(rmsg.Questions) == 0 {
		return 0, errors.New("no question")
	}

	// log.Info("tailscale dns query", "name", rmsg.Questions[0].Name, "type", rmsg.Questions[0].Type)

	msg, err := c.resolver.Raw(c.ctx, rmsg.Questions[0])
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
