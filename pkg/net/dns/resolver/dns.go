package resolver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/singleflight"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"github.com/miekg/dns"
)

var (
	bootstrap1, _ = NewDoH(Config{Host: "1.1.1.1", Dialer: direct.Default})
	bootstrap2, _ = NewDoH(Config{Host: "223.5.5.5", Dialer: direct.Default})
	group, _      = NewGroup(bootstrap1, bootstrap2)
	Internet      = NewClient(Config{Name: "internet"}, group)
)

func init() {
	dialer.SetBootstrap(Internet)
}

type Request struct {
	QuestionBytes []byte
	Question      dns.Question
	ID            uint16
	Truncated     bool
}

type Response interface {
	Msg() (dns.Msg, error)
	Release()
}

type BytesResponse []byte

func (b BytesResponse) Msg() (msg dns.Msg, err error) {
	var p dns.Msg
	err = p.Unpack(b)
	return p, err
}

func (b BytesResponse) Release() { pool.PutBytes(b) }

type MsgResponse dns.Msg

func (m MsgResponse) Msg() (msg dns.Msg, err error) {
	return dns.Msg(m), nil
}
func (m MsgResponse) Release() {}

type DialerFunc func(context.Context, *Request) (Response, error)

func (f DialerFunc) Do(ctx context.Context, req *Request) (Response, error) {
	return f(ctx, req)
}

func (f DialerFunc) Close() error { return nil }

type Dialer interface {
	Do(ctx context.Context, req *Request) (Response, error)
	Close() error
}

type Config struct {
	Dialer     netapi.Proxy
	Subnet     netip.Prefix
	Name       string
	Host       string
	Servername string
	Type       pd.Type
}

var dnsMap syncmap.SyncMap[pd.Type, func(Config) (Dialer, error)]

func New(config Config) (netapi.Resolver, error) {
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

func Register(tYPE pd.Type, f func(Config) (Dialer, error)) {
	if f != nil {
		dnsMap.Store(tYPE, f)
	}
}

var _ netapi.Resolver = (*client)(nil)

func CacheKeyFromQuestion(q dns.Question) string {
	return fmt.Sprintf("%s:%d", q.Name, q.Qtype)
}

type client struct {
	edns0             dns.RR
	dialer            Dialer
	rawStore          *lru.SyncLru[string, dns.Msg]
	rawSingleflight   singleflight.GroupSync[string, dns.Msg]
	refreshBackground syncmap.SyncMap[string, struct{}]
	config            Config
}

func NewClient(config Config, dialer Dialer) netapi.Resolver {
	optrbody := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  8192,
		},
	}

	optrbody.SetExtendedRcode(dns.RcodeSuccess)

	if config.Subnet.IsValid() {
		subnet := &dns.EDNS0_SUBNET{
			Code: dns.EDNS0SUBNET,
		}

		ip := config.Subnet.Masked().Addr()
		if ip.Is6() { // family https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
			subnet.Family = 2 // family ipv6 2
		} else {
			subnet.Family = 1 // family ipv4 1
		}

		mask := config.Subnet.Bits()
		subnet.SourceNetmask = uint8(mask)
		subnet.Address = ip.AsSlice()

		optrbody.Option = append(optrbody.Option, subnet)
	}

	c := &client{
		dialer: dialer,
		config: config,
		rawStore: lru.NewSyncLru(
			lru.WithCapacity[string, dns.Msg](int(configuration.DNSCache)),
			lru.WithDefaultTimeout[string, dns.Msg](time.Second*600),
		),
		edns0: optrbody,
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
		ips, err := c.lookupIP(ctx, domain, dns.Type(dns.TypeA))
		return &netapi.IPs{A: ips}, err
	case netapi.ResolverModePreferIPv6:
		log.Debug("lookup ipv6 only", "domain", domain)
		ips, err := c.lookupIP(ctx, domain, dns.Type(dns.TypeAAAA))
		return &netapi.IPs{AAAA: ips}, err
	case netapi.ResolverModeNoSpecified:
	}

	log.Debug("lookup ipv4 and ipv6", "domain", domain)

	wg := getWaitGroup()
	defer putWaitGroup(wg)

	wg.Add(1)
	var a []net.IP
	var aerr error

	go func() {
		defer wg.Done()
		a, aerr = c.lookupIP(ctx, domain, dns.Type(dns.TypeA))
	}()

	resp, aaaaerr := c.lookupIP(ctx, domain, dns.Type(dns.TypeAAAA))

	wg.Wait()

	if aerr != nil && aaaaerr != nil {
		return nil, mergerError(aerr, aaaaerr)
	}

	return &netapi.IPs{A: a, AAAA: resp}, nil
}

func mergerError(i4err, i6err error) error {
	i4e := &net.DNSError{}
	i6e := &net.DNSError{}

	if !errors.As(i4err, &i4e) || !errors.As(i6err, &i6e) {
		return fmt.Errorf("ipv6: %w, ipv4: %w", i6err, i4err)
	}

	if i4e.Err == i6e.Err {
		return i4e
	}

	return fmt.Errorf("ipv6: %w, ipv4: %w", i6err, i4err)
}

func (c *client) query(ctx context.Context, req dns.Question) (dns.Msg, error) {
	dialer := c.dialer

	reqMsg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 uint16(rand.UintN(math.MaxUint16)),
			Response:           false,
			Opcode:             0,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   true,
			RecursionAvailable: false,
			Rcode:              0,
		},
		Question: []dns.Question{req},
		Extra:    []dns.RR{c.edns0},
	}

	buf := pool.GetBytes(8192)
	defer pool.PutBytes(buf)

	bytes, err := reqMsg.PackBuffer(buf[:0])
	if err != nil {
		return dns.Msg{}, err
	}

	request := &Request{
		QuestionBytes: bytes,
		Question:      req,
		ID:            reqMsg.Id,
	}

	var msg dns.Msg

	for _, v := range []bool{false, true} {
		request.Truncated = v

		resp, err := dialer.Do(ctx, request)
		if err != nil {
			return dns.Msg{}, err
		}
		defer resp.Release()

		if msg, err = resp.Msg(); err != nil {
			return dns.Msg{}, err
		}

		if msg.Id != reqMsg.Id {
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
		ttl = msg.Answer[0].Header().Ttl
	}

	if req.Qtype == dns.TypeHTTPS {
		// remove ip hint, make safari use fakeip instead of ip hint
		c.removeIpHint(req, msg)
	}

	log.Select(slog.LevelDebug).PrintFunc("resolve domain", func() []any {
		args := []any{
			slog.String("resolver", c.config.Name),
			slog.Any("host", req.Name),
			slog.Any("type", dns.Type(req.Qtype)),
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

func (c *client) removeIpHint(req dns.Question, msg dns.Msg) {
	for _, r := range msg.Answer {
		if r.Header().Rrtype != dns.TypeHTTPS {
			continue
		}

		https, ok := r.(*dns.HTTPS)
		if !ok {
			continue
		}

		news := https.SVCB.Value[:0]

		for _, v := range https.SVCB.Value {
			if v.Key() == dns.SVCB_IPV4HINT || v.Key() == dns.SVCB_IPV6HINT {
				c.iphintToCache(req.Name, r.Header().Ttl, v)
				continue
			}

			news = append(news, v)
		}

		https.Value = news
	}
}

func (c *client) iphintToCache(name string, ttl uint32, vv dns.SVCBKeyValue) {
	var qtype uint16
	var answers []dns.RR
	switch z := vv.(type) {
	case *dns.SVCBIPv4Hint:
		qtype = dns.TypeA
		for _, v := range z.Hint {
			answers = append(answers, &dns.A{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeA,
					Ttl:    ttl,
					Class:  dns.ClassINET,
				},
				A: v,
			})
		}
	case *dns.SVCBIPv6Hint:
		qtype = dns.TypeAAAA
		for _, v := range z.Hint {
			answers = append(answers, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeAAAA,
					Ttl:    ttl,
					Class:  dns.ClassINET,
				},
				AAAA: v,
			})
		}
	default:
		return
	}

	if len(answers) == 0 {
		return
	}

	req := dns.Question{
		Name:   name,
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}
	c.rawStore.Add(CacheKeyFromQuestion(req),
		dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:                 0,
				Response:           true,
				Opcode:             0,
				Authoritative:      false,
				Truncated:          false,
				RecursionDesired:   true,
				RecursionAvailable: true,
				Rcode:              dns.RcodeSuccess,
			},
			Question: []dns.Question{req},
			Answer:   answers,
		},
		lru.WithTimeout[string, dns.Msg](time.Duration(ttl)*time.Second),
	)
}

func (c *client) Raw(ctx context.Context, req dns.Question) (dns.Msg, error) {
	rawmsg, err := c.raw(ctx, req)
	if err != nil {
		return dns.Msg{}, err
	}

	rawmsg = *rawmsg.Copy()
	rawmsg.Question = []dns.Question{req}
	return rawmsg, nil
}

func (c *client) raw(ctx context.Context, req dns.Question) (dns.Msg, error) {
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
			msg, err := c.query(ctx, req)
			if err != nil {
				return dns.Msg{}, err
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

				_, err := c.query(ctx, req)
				if err != nil {
					log.Error("refresh domain background failed", "req", req, "err", err)
				}
			}()
		}
	}

	return rawmsg, nil
}

func (c *client) lookupIP(ctx context.Context, domain string, reqType dns.Type) ([]net.IP, error) {
	if len(domain) == 0 {
		return nil, fmt.Errorf("empty domain")
	}

	domain = system.AbsDomain(domain)

	rawmsg, err := c.raw(ctx, dns.Question{
		Name:   domain,
		Qtype:  uint16(reqType),
		Qclass: dns.ClassINET,
	})
	if err != nil {
		return nil, fmt.Errorf("send dns message failed: %w", err)
	}

	if rawmsg.Rcode != dns.RcodeSuccess {
		metrics.Counter.AddFailedDNS(domain, rawmsg.Rcode, reqType)
		return nil, &net.DNSError{
			Err:         dns.RcodeToString[rawmsg.Rcode],
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
			if v.Header().Rrtype != dns.TypeA {
				continue
			}

			ips = append(ips, v.(*dns.A).A)
		}
	case dns.TypeAAAA:
		ips = make([]net.IP, 0, len(rawmsg.Answer))

		for _, v := range rawmsg.Answer {
			if v.Header().Rrtype != dns.TypeAAAA {
				continue
			}

			ips = append(ips, v.(*dns.AAAA).AAAA)
		}
	}

	if len(ips) == 0 {
		metrics.Counter.AddFailedDNS(domain, dns.RcodeSuccess, reqType)
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

func appendIPHint(msg dns.Msg, ipv4, ipv6 []net.IP) {
	if len(ipv4) == 0 && len(ipv6) == 0 {
		return
	}

	for _, v := range msg.Answer {
		if v.Header().Rrtype != dns.TypeHTTPS {
			continue
		}

		https, ok := v.(*dns.HTTPS)
		if !ok {
			continue
		}

		// the raw message already cloned, so we no need copy anymore here
		if len(ipv4) > 0 {
			https.Value = append(https.Value, &dns.SVCBIPv4Hint{
				Hint: ipv4,
			})
		}

		if len(ipv6) > 0 {
			https.Value = append(https.Value, &dns.SVCBIPv6Hint{
				Hint: ipv6,
			})
		}

		break
	}
}
