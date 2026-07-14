package netapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
)

type LookupIPOption struct {
	Mode ResolverMode
}

type IPs struct {
	AAAA []net.IP
	A    []net.IP
}

// DNSQuestion is the application-level representation of a DNS question.
// miekg/dns v2 represents questions as RRs, while the rest of yuhaiin only
// needs the question header. Keeping that boundary explicit avoids leaking
// the wire-library representation through resolver interfaces.
type DNSQuestion struct {
	Name   string
	Qtype  uint16
	Qclass uint16
}

func DNSQuestionFromRR(rr dns.RR) DNSQuestion {
	if rr == nil {
		return DNSQuestion{}
	}
	return DNSQuestion{
		Name:   rr.Header().Name,
		Qtype:  dns.RRToType(rr),
		Qclass: rr.Header().Class,
	}
}

func (q DNSQuestion) RR() dns.RR {
	newRR, ok := dns.TypeToRR[q.Qtype]
	if !ok {
		return nil
	}
	rr := newRR()
	rr.Header().Name = q.Name
	rr.Header().Class = q.Qclass
	return rr
}

func NewDNSMsg(q DNSQuestion) *dns.Msg {
	m := &dns.Msg{
		MsgHeader: dns.MsgHeader{
			Response:           true,
			Opcode:             dns.OpcodeQuery,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   true,
			RecursionAvailable: true,
			Rcode:              dns.RcodeSuccess,
		},
	}
	if rr := q.RR(); rr != nil {
		m.Question = []dns.RR{rr}
	}
	return m
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

func (i *IPs) RandNetipAddr() netip.Addr {
	addr, _ := netip.AddrFromSlice(i.Rand())
	return addr.Unmap()
}

func (i *IPs) RandUDPAddr(port uint16) *net.UDPAddr {
	return &net.UDPAddr{IP: i.Rand(), Port: int(port)}
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
	Raw(ctx context.Context, req DNSQuestion) (*dns.Msg, error)
	io.Closer
	Name() string
}

var _ Resolver = (*ErrorResolver)(nil)

type ErrorResolver func(domain string) error

func (e ErrorResolver) LookupIP(_ context.Context, domain string, opts ...func(*LookupIPOption)) (*IPs, error) {
	return &IPs{}, e(domain)
}
func (e ErrorResolver) Close() error { return nil }
func (e ErrorResolver) Raw(_ context.Context, req DNSQuestion) (*dns.Msg, error) {
	return NewDNSMsg(req), nil
}
func (e ErrorResolver) Name() string { return "ErrorResolver" }

// dnsConn is a net.PacketConn suitable for returning from
// net.Dialer.Dial to send DNS queries over Bootstrap.
type dnsConn struct {
	resolver Resolver
	rbuf     bytes.Buffer
}

func NewDnsConn(resolver Resolver) *dnsConn {
	return &dnsConn{resolver: resolver}
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
	rmsg.Data = packet
	if err = rmsg.Unpack(); err != nil {
		return 0, err
	}

	if len(rmsg.Question) == 0 {
		return 0, errors.New("no question")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()
	msg, err := c.resolver.Raw(ctx, DNSQuestionFromRR(rmsg.Question[0]))
	if err != nil {
		return 0, err
	}

	msg.ID = rmsg.ID

	if err := msg.Pack(); err != nil {
		return 0, err
	}
	data := msg.Data

	c.rbuf.Reset()
	c.rbuf.Write(data)

	return len(packet), nil
}

type todoAddr struct{}

func (todoAddr) Network() string { return "unused" }
func (todoAddr) String() string  { return "unused-todoAddr" }

type DynamicResolver struct {
	r  Resolver
	mu sync.RWMutex
}

func NewDynamicResolver(r Resolver) *DynamicResolver {
	return &DynamicResolver{r: r}
}

func (r *DynamicResolver) getResolver() Resolver {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.r
}

func (r *DynamicResolver) LookupIP(ctx context.Context, domain string, opts ...func(*LookupIPOption)) (*IPs, error) {
	return r.getResolver().LookupIP(ctx, domain, opts...)
}

func (r *DynamicResolver) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.r.Close()
}

func (r *DynamicResolver) Raw(ctx context.Context, req DNSQuestion) (*dns.Msg, error) {
	return r.getResolver().Raw(ctx, req)
}

func (r *DynamicResolver) Set(r2 Resolver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.r = r2
}

var bootstrap = &bootstrapResolver{}

func init() {
	net.DefaultResolver = &net.Resolver{
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return NewDnsConn(Bootstrap()), nil
		},
	}
}

type bootstrapResolver struct {
	r  Resolver
	mu sync.RWMutex
}

func (b *bootstrapResolver) LookupIP(ctx context.Context, domain string, opts ...func(*LookupIPOption)) (*IPs, error) {
	b.mu.RLock()
	r := b.r
	b.mu.RUnlock()

	if r == nil {
		return nil, errors.New("bootstrap resolver is not initialized")
	}

	return r.LookupIP(ctx, domain, opts...)
}

func (b *bootstrapResolver) Raw(ctx context.Context, req DNSQuestion) (*dns.Msg, error) {
	b.mu.RLock()
	r := b.r
	b.mu.RUnlock()

	if r == nil {
		return nil, errors.New("bootstrap resolver is not initialized")
	}

	return r.Raw(ctx, req)
}

func (b *bootstrapResolver) Name() string {
	b.mu.RLock()
	r := b.r
	b.mu.RUnlock()
	if r == nil {
		return "bootstrap"
	}

	name := r.Name()
	if strings.ToLower(name) == "bootstrap" {
		return name
	}

	return fmt.Sprintf("bootstrap(%s)", name)
}

func (b *bootstrapResolver) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	var err error
	if b.r != nil {
		err = b.r.Close()
		b.r = nil
	}

	return err
}

func (b *bootstrapResolver) SetBootstrap(r Resolver) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.r != nil {
		if err := b.r.Close(); err != nil {
			slog.Warn("close bootstrap resolver failed", "err", err)
		}
	}

	b.r = r
}

func Bootstrap() Resolver     { return bootstrap }
func SetBootstrap(r Resolver) { bootstrap.SetBootstrap(r) }

func ResolverIP(ctx context.Context, addr string) (*IPs, error) {
	netctx := GetContext(ctx).ConnOptions().Resolver()

	resolver := netctx.Resolver()
	if resolver == nil {
		resolver = Bootstrap()
	}

	if netctx.Mode() != ResolverModeNoSpecified {
		ips, err := resolver.LookupIP(ctx, addr, netctx.Opts(false)...)
		if err == nil {
			return ips, nil
		}
	}

	ips, err := resolver.LookupIP(ctx, addr, netctx.Opts(true)...)
	if err != nil {
		return nil, fmt.Errorf("resolve address(%v) failed: %w", addr, err)
	}

	return ips, nil
}
