package resolver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	"codeberg.org/miekg/dns/svcb"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"github.com/Asutorufa/yuhaiin/pkg/utils/singleflight"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

var (
	bootstrap1, _ = NewDoH(Config{Host: "1.1.1.1", Dialer: direct.Default})
	bootstrap2, _ = NewDoH(Config{Host: "223.5.5.5", Dialer: direct.Default})
	group, _      = NewGroup(bootstrap1, bootstrap2)
	Internet      = nopCloser{NewClient(Config{Name: "internet"}, group)}
)

type nopCloser struct {
	netapi.Resolver
}

func (n nopCloser) Close() error { return nil }

func init() {
	netapi.SetBootstrap(Internet)
}

type Request struct {
	dnsRequestBytes []byte
	Question        netapi.DNSQuestion
	ID              uint16
	Truncated       bool
}

func (r *Request) Bytes() []byte { return r.dnsRequestBytes }

type TransportFunc func(context.Context, *Request) (dns.Msg, error)

func (f TransportFunc) Do(ctx context.Context, req *Request) (dns.Msg, error) {
	return f(ctx, req)
}

func (f TransportFunc) Close() error { return nil }

type Transport interface {
	Do(ctx context.Context, req *Request) (dns.Msg, error)
	Close() error
}

type Config struct {
	Dialer     netapi.Proxy
	Subnet     netip.Prefix
	Name       string
	Host       string
	Servername string
	Type       string
}

func (c *Config) serverName(u *url.URL) string {
	if c.Servername == "" {
		return u.Hostname()
	}

	return c.Servername
}

var dnsMap syncmap.SyncMap[string, func(Config) (Transport, error)]

func New(config Config) (netapi.Resolver, error) {
	if config.Type == "" {
		config.Type = "udp"
	}
	f, ok := dnsMap.Load(config.Type)
	if !ok {
		return nil, fmt.Errorf("no dns type %v process found", config.Type)
	}

	if config.Dialer == nil {
		config.Dialer = direct.Default
	}
	dialer, err := f(config)
	if err != nil {
		return nil, err
	}

	return NewClient(config, dialer), nil
}

func Register(tYPE string, f func(Config) (Transport, error)) {
	if f != nil {
		dnsMap.Store(tYPE, f)
	}
}

var _ netapi.Resolver = (*client)(nil)

func CacheKeyFromQuestion(q netapi.DNSQuestion) string {
	return fmt.Sprintf("%s:%d", q.Name, q.Qtype)
}

type client struct {
	edns0             dns.EDNS0
	dialer            Transport
	rawStore          *lru.SyncLru[string, dns.Msg]
	config            Config
	rawSingleflight   singleflight.GroupSync[string, dns.Msg]
	refreshBackground syncmap.SyncMap[string, struct{}]
}

func NewClient(config Config, dialer Transport) netapi.Resolver {
	var subnet *dns.SUBNET
	if config.Subnet.IsValid() {
		subnet = &dns.SUBNET{}

		ip := config.Subnet.Masked().Addr()
		if ip.Is6() { // family https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
			subnet.Family = 2 // family ipv6 2
		} else {
			subnet.Family = 1 // family ipv4 1
		}

		subnet.Netmask = uint8(config.Subnet.Bits())
		subnet.Address = ip
	}
	var edns0 dns.EDNS0
	if subnet != nil {
		edns0 = subnet
	}

	c := &client{
		dialer: dialer,
		config: config,
		rawStore: lru.NewSyncLru(
			lru.WithCapacity[string, dns.Msg](int(configuration.DNSCache)),
			lru.WithDefaultTimeout[string, dns.Msg](time.Second*600),
		),
		edns0: edns0,
	}

	return c
}

var waitGroupPool = sync.Pool{New: func() any { return &sync.WaitGroup{} }}

func getWaitGroup() *sync.WaitGroup   { return waitGroupPool.Get().(*sync.WaitGroup) }
func putWaitGroup(wg *sync.WaitGroup) { waitGroupPool.Put(wg) }

func (c *client) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	opt := &netapi.LookupIPOption{}

	for _, optf := range opts {
		optf(opt)
	}

	// only ipv6/ipv4
	switch opt.Mode {
	case netapi.ResolverModePreferIPv4:
		log.Debug("lookup ipv4 only", "domain", domain)
		ips, err := c.lookupIP(ctx, domain, dns.TypeA)
		return &netapi.IPs{A: ips}, err
	case netapi.ResolverModePreferIPv6:
		log.Debug("lookup ipv6 only", "domain", domain)
		ips, err := c.lookupIP(ctx, domain, dns.TypeAAAA)
		return &netapi.IPs{AAAA: ips}, err
	case netapi.ResolverModeNoSpecified:
	}

	log.Debug("lookup ipv4 and ipv6", "domain", domain)

	wg := getWaitGroup()
	defer putWaitGroup(wg)

	var a []net.IP
	var aerr error

	wg.Go(func() { a, aerr = c.lookupIP(ctx, domain, dns.TypeA) })

	resp, aaaaerr := c.lookupIP(ctx, domain, dns.TypeAAAA)

	wg.Wait()

	if aerr != nil && aaaaerr != nil {
		return nil, mergerError(aerr, aaaaerr)
	}

	return &netapi.IPs{A: a, AAAA: resp}, nil
}

func mergerError(i4err, i6err error) error {
	i4e, ok4 := errors.AsType[*net.DNSError](i4err)
	i6e, ok6 := errors.AsType[*net.DNSError](i6err)

	if !ok4 || !ok6 {
		return fmt.Errorf("ipv6: %w, ipv4: %w", i6err, i4err)
	}

	if i4e.Err == i6e.Err {
		return i4e
	}

	return fmt.Errorf("ipv6: %w, ipv4: %w", i6err, i4err)
}

func (c *client) queryWithMetrics(ctx context.Context, req netapi.DNSQuestion) (dns.Msg, error) {
	metrics.Counter.AddDnsQuery(c.config.Name)
	now := system.CheapNowNano()
	msg, err := c.query(ctx, req)
	if err == nil {
		metrics.Counter.AddDnsQueryDuration(c.config.Name, float64(time.Duration(system.CheapNowNano()-now).Milliseconds()))
	} else {
		metrics.Counter.AddDnsQueryError(c.config.Name)
	}
	return msg, err
}

func (c *client) query(ctx context.Context, req netapi.DNSQuestion) (dns.Msg, error) {
	dialer := c.dialer

	reqMsg := &dns.Msg{
		MsgHeader: dns.MsgHeader{
			ID:                 dns.ID(),
			Response:           false,
			Opcode:             0,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   true,
			RecursionAvailable: false,
			Rcode:              0,
			UDPSize:            8192,
		},
		Question: []dns.RR{req.RR()},
	}
	if c.edns0 != nil {
		reqMsg.Pseudo = []dns.RR{c.edns0.Clone()}
	}
	if err := reqMsg.Pack(); err != nil {
		return dns.Msg{}, err
	}
	bytes := reqMsg.Data

	request := &Request{
		dnsRequestBytes: bytes,
		Question:        req,
		ID:              reqMsg.ID,
	}

	var (
		msg dns.Msg
		err error
	)

	for _, v := range []bool{false, true} {
		request.Truncated = v

		msg, err = dialer.Do(ctx, request)
		if err != nil {
			return dns.Msg{}, fmt.Errorf("dns client do failed: %w", err)
		}

		if msg.ID != reqMsg.ID {
			return dns.Msg{}, fmt.Errorf("id not match")
		}

		if !msg.Truncated {
			break
		}

		// If TC is set, the choice of records in the answer (if any)
		// do not really matter much as the client is supposed to
		// just discard the message and retry over TCP, anyway.
		//
		// https://serverfault.com/questions/991520/how-is-truncation-performed-in-dns-according-to-rfc-1035
	}

	ttl := uint32(300)
	if len(msg.Answer) > 0 {
		ttl = msg.Answer[0].Header().TTL
	}

	if req.Qtype == dns.TypeHTTPS {
		// remove ip hint, make safari use fakeip instead of ip hint
		c.removeIpHint(req, msg)
	}

	log.Select(slog.LevelDebug).PrintFunc("resolve domain", func() []any {
		args := []any{
			slog.String("resolver", c.config.Name),
			slog.Any("host", req.Name),
			slog.Any("type", dnsutil.TypeToString(req.Qtype)),
			slog.Any("code", msg.Rcode),
			slog.Any("ttl", ttl),
		}
		return args
	})

	if ttl > 1 {
		msg.Question = nil
		c.rawStore.Add(CacheKeyFromQuestion(req), msg,
			lru.WithTimeout[string, dns.Msg](time.Duration(ttl)*time.Second))
	}

	return msg, nil
}

func (c *client) removeIpHint(req netapi.DNSQuestion, msg dns.Msg) {
	for _, r := range msg.Answer {
		if dns.RRToType(r) != dns.TypeHTTPS {
			continue
		}

		https, ok := r.(*dns.HTTPS)
		if !ok {
			continue
		}

		news := https.Value[:0]

		for _, v := range https.Value {
			if key := svcb.PairToKey(v); key == svcb.KeyIPv4Hint || key == svcb.KeyIPv6Hint {
				c.iphintToCache(req.Name, r.Header().TTL, v)
				continue
			}

			news = append(news, v)
		}

		https.Value = news
	}
}

func (c *client) iphintToCache(name string, ttl uint32, vv svcb.Pair) {
	var qtype uint16
	var answers []dns.RR
	switch z := vv.(type) {
	case *svcb.IPV4HINT:
		qtype = dns.TypeA
		for _, v := range z.Hint {
			answers = append(answers, &dns.A{
				Hdr: dns.Header{
					Name:  name,
					TTL:   ttl,
					Class: dns.ClassINET,
				},
				A: rdata.A{Addr: v},
			})
		}
	case *svcb.IPV6HINT:
		qtype = dns.TypeAAAA
		for _, v := range z.Hint {
			answers = append(answers, &dns.AAAA{
				Hdr: dns.Header{
					Name:  name,
					TTL:   ttl,
					Class: dns.ClassINET,
				},
				AAAA: rdata.AAAA{Addr: v},
			})
		}
	default:
		return
	}

	if len(answers) == 0 {
		return
	}

	req := netapi.DNSQuestion{
		Name:   name,
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}
	c.rawStore.Add(CacheKeyFromQuestion(req),
		dns.Msg{
			MsgHeader: dns.MsgHeader{
				ID:                 0,
				Response:           true,
				Opcode:             0,
				Authoritative:      false,
				Truncated:          false,
				RecursionDesired:   true,
				RecursionAvailable: true,
				Rcode:              dns.RcodeSuccess,
			},
			Question: []dns.RR{req.RR()},
			Answer:   answers,
		},
		lru.WithTimeout[string, dns.Msg](time.Duration(ttl)*time.Second),
	)
}

func (c *client) Raw(ctx context.Context, req netapi.DNSQuestion) (dns.Msg, error) {
	rawmsg, err := c.raw(ctx, req)
	if err != nil {
		return dns.Msg{}, err
	}

	rawmsg = *rawmsg.Copy()
	rawmsg.Question = []dns.RR{req.RR()}
	return rawmsg, nil
}

func (c *client) raw(ctx context.Context, req netapi.DNSQuestion) (dns.Msg, error) {
	if !system.IsDomainName(req.Name) {
		return dns.Msg{}, fmt.Errorf("invalid domain: %s", req.Name)
	}

	if req.Qclass == 0 {
		req.Qclass = dns.ClassINET
	}

	cacheKey := CacheKeyFromQuestion(req)

	rawmsg, expired, ok := c.rawStore.LoadOptimistically(cacheKey)
	if !ok {
		var err error
		rawmsg, err, _ = c.rawSingleflight.Do(ctx, cacheKey, func(ctx context.Context) (dns.Msg, error) {
			msg, err := c.queryWithMetrics(ctx, req)
			if err != nil {
				return dns.Msg{}, fmt.Errorf("query with metrics failed: %w", err)
			}
			return msg, nil
		})
		if err != nil {
			return dns.Msg{}, err
		}
	}

	if expired {
		if _, ok = c.refreshBackground.LoadOrStore(cacheKey, struct{}{}); !ok {
			// refresh expired response background
			go func() {
				defer c.refreshBackground.Delete(cacheKey)

				ctx = context.WithoutCancel(ctx)
				ctx, cancel := context.WithTimeout(ctx, configuration.ResolverTimeout)
				defer cancel()

				_, err := c.queryWithMetrics(ctx, req)
				if err != nil {
					log.Error("refresh domain background failed", "req", req, "err", err)
				}
			}()
		}
	}

	return rawmsg, nil
}

func (c *client) lookupIP(ctx context.Context, domain string, reqType uint16) ([]net.IP, error) {
	if len(domain) == 0 {
		return nil, fmt.Errorf("empty domain")
	}

	metrics.Counter.AddLookupIP(reqType)

	domain = system.AbsDomain(domain)

	rawmsg, err := c.raw(ctx, netapi.DNSQuestion{
		Name:   domain,
		Qtype:  uint16(reqType),
		Qclass: dns.ClassINET,
	})
	if err != nil {
		metrics.Counter.AddLookupIPFailed("RAWFAIL", reqType)
		return nil, fmt.Errorf("send dns message failed: %w", err)
	}

	if rawmsg.Rcode != dns.RcodeSuccess {
		metrics.Counter.AddLookupIPFailed(dnsutil.RcodeToString(rawmsg.Rcode), reqType)
		return nil, &net.DNSError{
			Err:         dnsutil.RcodeToString(rawmsg.Rcode),
			Server:      c.config.Host,
			Name:        domain,
			IsNotFound:  true,
			IsTemporary: true,
		}
	}

	var ips []net.IP

	switch uint16(reqType) {
	case dns.TypeA:
		ips = make([]net.IP, 0, len(rawmsg.Answer))

		for _, v := range rawmsg.Answer {
			if dns.RRToType(v) != dns.TypeA {
				continue
			}

			ips = append(ips, v.(*dns.A).A.Addr.AsSlice())
		}
	case dns.TypeAAAA:
		ips = make([]net.IP, 0, len(rawmsg.Answer))

		for _, v := range rawmsg.Answer {
			if dns.RRToType(v) != dns.TypeAAAA {
				continue
			}

			ips = append(ips, v.(*dns.AAAA).AAAA.Addr.AsSlice())
		}
	}

	if len(ips) == 0 {
		metrics.Counter.AddLookupIPFailed("ZEROIP", reqType)
		return nil, &net.DNSError{
			Err:         "no such host",
			Server:      c.config.Host,
			Name:        domain,
			IsNotFound:  true,
			IsTemporary: true,
		}
	}

	return ips, nil
}

func (c *client) Close() error { return c.dialer.Close() }

func (c *client) Name() string { return c.config.Name }
