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
	"slices"
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
	dnsmessage "github.com/miekg/dns"
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
	Question      dnsmessage.Question
	ID            uint16
	Truncated     bool
}

type Response interface {
	Msg() (dnsmessage.Msg, error)
	Release()
}

type BytesResponse []byte

func (b BytesResponse) Msg() (msg dnsmessage.Msg, err error) {
	var p dnsmessage.Msg
	err = p.Unpack(b)
	return p, err
}

func (b BytesResponse) Release() { pool.PutBytes(b) }

type MsgResponse dnsmessage.Msg

func (m MsgResponse) Msg() (msg dnsmessage.Msg, err error) {
	return dnsmessage.Msg(m), nil
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

type CacheKey struct {
	Name string
	Type dnsmessage.Type
}

func CacheKeyFromQuestion(q dnsmessage.Question) CacheKey {
	var name string = q.Name

	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}

	return CacheKey{
		Name: name,
		Type: dnsmessage.Type(q.Qtype),
	}
}

type client struct {
	edns0             dnsmessage.RR
	dialer            Dialer
	rawStore          *lru.SyncLru[CacheKey, *rawEntry]
	rawSingleflight   singleflight.GroupSync[dnsmessage.Question, *rawEntry]
	refreshBackground syncmap.SyncMap[dnsmessage.Question, struct{}]
	config            Config
}

func NewClient(config Config, dialer Dialer) *client {
	optrbody := &dnsmessage.OPT{
		Hdr: dnsmessage.RR_Header{
			Name:   ".",
			Rrtype: dnsmessage.TypeOPT,
			Class:  8192,
		},
	}

	optrbody.SetExtendedRcode(dnsmessage.RcodeSuccess)

	if config.Subnet.IsValid() {
		subnet := &dnsmessage.EDNS0_SUBNET{
			Code: dnsmessage.EDNS0SUBNET,
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
			lru.WithCapacity[CacheKey, *rawEntry](configuration.DNSCache),
			lru.WithDefaultTimeout[CacheKey, *rawEntry](time.Second*600),
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
		ips, err := c.lookupIP(ctx, domain, dnsmessage.Type(dnsmessage.TypeA))
		return &netapi.IPs{A: ips}, err
	case netapi.ResolverModePreferIPv6:
		log.Debug("lookup ipv6 only", "domain", domain)
		ips, err := c.lookupIP(ctx, domain, dnsmessage.Type(dnsmessage.TypeAAAA))
		return &netapi.IPs{AAAA: ips}, err
	}

	log.Debug("lookup ipv4 and ipv6", "domain", domain)

	wg := getWaitGroup()
	defer putWaitGroup(wg)

	wg.Add(1)
	var a []net.IP
	var aerr error

	go func() {
		defer wg.Done()
		a, aerr = c.lookupIP(ctx, domain, dnsmessage.Type(dnsmessage.TypeA))
	}()

	resp, aaaaerr := c.lookupIP(ctx, domain, dnsmessage.Type(dnsmessage.TypeAAAA))

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

func (c *client) query(ctx context.Context, req dnsmessage.Question) (dnsmessage.Msg, error) {
	dialer := c.dialer

	reqMsg := dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Id:                 uint16(rand.UintN(math.MaxUint16)),
			Response:           false,
			Opcode:             0,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   true,
			RecursionAvailable: false,
			Rcode:              0,
		},
		Question: []dnsmessage.Question{req},
		Extra:    []dnsmessage.RR{c.edns0},
	}

	buf := pool.GetBytes(8192)
	defer pool.PutBytes(buf)

	bytes, err := reqMsg.PackBuffer(buf[:0])
	if err != nil {
		return dnsmessage.Msg{}, err
	}

	request := &Request{
		QuestionBytes: bytes,
		Question:      req,
		ID:            reqMsg.Id,
	}

	var msg dnsmessage.Msg

	for _, v := range []bool{false, true} {
		request.Truncated = v

		resp, err := dialer.Do(ctx, request)
		if err != nil {
			return dnsmessage.Msg{}, err
		}
		defer resp.Release()

		if msg, err = resp.Msg(); err != nil {
			return dnsmessage.Msg{}, err
		}

		if msg.Id != reqMsg.Id {
			return dnsmessage.Msg{}, fmt.Errorf("id not match")
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

	ttl := uint32(600)
	if len(msg.Answer) > 0 {
		ttl = msg.Answer[0].Header().Ttl
	}

	if req.Qtype == dnsmessage.TypeHTTPS {
		// remove ip hint, make safari use fakeip instead of ip hint
		for _, r := range msg.Answer {
			if r.Header().Rrtype != dnsmessage.TypeHTTPS {
				continue
			}

			https, ok := r.(*dnsmessage.HTTPS)
			if !ok {
				continue
			}

			news := make([]dnsmessage.SVCBKeyValue, 0, len(https.SVCB.Value))
			for _, v := range https.SVCB.Value {
				if v.Key() == dnsmessage.SVCB_IPV4HINT || v.Key() == dnsmessage.SVCB_IPV6HINT {
					c.iphintToCache(req.Name, r.Header().Ttl, v)
					continue
				}

				news = append(news, v)
			}

			https.Value = news
		}
	}

	log.Select(slog.LevelDebug).PrintFunc("resolve domain", func() []any {
		args := []any{
			slog.String("resolver", c.config.Name),
			slog.Any("host", req.Name),
			slog.Any("type", dnsmessage.Type(req.Qtype)),
			slog.Any("code", msg.Rcode),
			slog.Any("ttl", ttl),
		}
		return args
	})

	if ttl > 1 {
		msg.Question = nil
		c.rawStore.Add(CacheKeyFromQuestion(req), newRawEntry(msg),
			lru.WithTimeout[CacheKey, *rawEntry](time.Duration(ttl)*time.Second))
	}

	return msg, nil
}

func (c *client) iphintToCache(name string, ttl uint32, vv dnsmessage.SVCBKeyValue) {
	var qtype uint16
	var answers []dnsmessage.RR
	switch z := vv.(type) {
	case *dnsmessage.SVCBIPv4Hint:
		qtype = dnsmessage.TypeA
		for _, v := range z.Hint {
			answers = append(answers, &dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   name,
					Rrtype: dnsmessage.TypeA,
					Ttl:    ttl,
					Class:  dnsmessage.ClassINET,
				},
				A: v,
			})
		}
	case *dnsmessage.SVCBIPv6Hint:
		qtype = dnsmessage.TypeAAAA
		for _, v := range z.Hint {
			answers = append(answers, &dnsmessage.AAAA{
				Hdr: dnsmessage.RR_Header{
					Name:   name,
					Rrtype: dnsmessage.TypeAAAA,
					Ttl:    ttl,
					Class:  dnsmessage.ClassINET,
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

	req := dnsmessage.Question{
		Name:   name,
		Qtype:  qtype,
		Qclass: dnsmessage.ClassINET,
	}
	c.rawStore.Add(CacheKeyFromQuestion(req),
		newRawEntry(dnsmessage.Msg{
			MsgHdr: dnsmessage.MsgHdr{
				Id:                 0,
				Response:           true,
				Opcode:             0,
				Authoritative:      false,
				Truncated:          false,
				RecursionDesired:   true,
				RecursionAvailable: true,
				Rcode:              dnsmessage.RcodeSuccess,
			},
			Question: []dnsmessage.Question{req},
			Answer:   answers,
		}),
		lru.WithTimeout[CacheKey, *rawEntry](time.Duration(ttl)*time.Second),
	)
}

func (c *client) Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Msg, error) {
	rawmsg, err := c.raw(ctx, req)
	if err != nil {
		return dnsmessage.Msg{}, err
	}

	msg := rawmsg.Message()

	msg.Question = []dnsmessage.Question{req}

	// TODO deep copy resource.Body
	msg.Answer = slices.Clone(msg.Answer)
	msg.Ns = slices.Clone(msg.Ns)
	msg.Extra = slices.Clone(msg.Extra)

	return msg, nil
}

func (c *client) raw(ctx context.Context, req dnsmessage.Question) (*rawEntry, error) {
	if !system.IsDomainName(req.Name) {
		return nil, fmt.Errorf("invalid domain: %s", req.Name)
	}

	if req.Qclass == 0 {
		req.Qclass = dnsmessage.ClassINET
	}

	rawmsg, expired, ok := c.rawStore.LoadOptimistically(CacheKeyFromQuestion(req))
	if !ok {
		var err error
		rawmsg, err, _ = c.rawSingleflight.Do(ctx, req, func(ctx context.Context) (*rawEntry, error) {
			msg, err := c.query(ctx, req)
			if err != nil {
				return nil, err
			}
			return newRawEntry(msg), nil
		})
		if err != nil {
			return nil, err
		}
	}

	if expired {
		if _, ok = c.refreshBackground.LoadOrStore(req, struct{}{}); !ok {
			// refresh expired response background
			go func() {
				defer c.refreshBackground.Delete(req)

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

func (c *client) lookupIP(ctx context.Context, domain string, reqType dnsmessage.Type) ([]net.IP, error) {
	if len(domain) == 0 {
		return nil, fmt.Errorf("empty domain")
	}

	domain = system.AbsDomain(domain)

	rawmsg, err := c.raw(ctx, dnsmessage.Question{
		Name:   domain,
		Qtype:  uint16(reqType),
		Qclass: dnsmessage.ClassINET,
	})
	if err != nil {
		return nil, fmt.Errorf("send dns message failed: %w", err)
	}

	if rawmsg.RCode() != dnsmessage.RcodeSuccess {
		metrics.Counter.AddFailedDNS(domain, rawmsg.RCode(), reqType)
		return nil, &net.DNSError{
			Err:         dnsmessage.RcodeToString[rawmsg.RCode()],
			Server:      c.config.Host,
			Name:        domain,
			IsNotFound:  true,
			IsTemporary: true,
		}
	}

	var ips []net.IP

	switch uint16(reqType) {
	case dnsmessage.TypeA:
		ips = rawmsg.A()
	case dnsmessage.TypeAAAA:
		ips = rawmsg.AAAA()
	}

	if len(ips) == 0 {
		metrics.Counter.AddFailedDNS(domain, dnsmessage.RcodeSuccess, reqType)
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

type rawEntry struct {
	mu   sync.RWMutex
	msg  dnsmessage.Msg
	ipv4 []net.IP
	ipv6 []net.IP
}

func newRawEntry(msg dnsmessage.Msg) *rawEntry {
	return &rawEntry{
		msg: msg,
	}
}

func (r *rawEntry) Message() dnsmessage.Msg {
	return r.msg
}

func (r *rawEntry) RCode() int {
	return r.msg.Rcode
}

func (r *rawEntry) A() []net.IP {
	r.mu.RLock()
	ips := r.ipv4
	r.mu.RUnlock()

	if ips != nil {
		return ips
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.ipv4 != nil {
		return r.ipv4
	}

	r.ipv4 = make([]net.IP, 0, len(r.msg.Answer))

	for _, v := range r.msg.Answer {
		if v.Header().Rrtype != dnsmessage.TypeA {
			continue
		}

		r.ipv4 = append(r.ipv4, v.(*dnsmessage.A).A)
	}

	return r.ipv4
}

func (r *rawEntry) AAAA() []net.IP {
	r.mu.RLock()
	ips := r.ipv6
	r.mu.RUnlock()

	if ips != nil {
		return ips
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.ipv6 != nil {
		return r.ipv6
	}

	r.ipv6 = make([]net.IP, 0, len(r.msg.Answer))

	for _, v := range r.msg.Answer {
		if v.Header().Rrtype != dnsmessage.TypeAAAA {
			continue
		}

		r.ipv6 = append(r.ipv6, v.(*dnsmessage.AAAA).AAAA)
	}

	return r.ipv6
}

func appendIPHint(msg dnsmessage.Msg, ipv4, ipv6 []net.IP) {
	if len(ipv4) == 0 && len(ipv6) == 0 {
		return
	}

	for i, v := range msg.Answer {
		if v.Header().Rrtype != dnsmessage.TypeHTTPS {
			continue
		}

		https, ok := v.(*dnsmessage.HTTPS)
		if !ok {
			continue
		}

		newHttps := &dnsmessage.HTTPS{}

		*newHttps = *https

		if len(ipv4) > 0 {
			newHttps.Value = append(newHttps.Value, &dnsmessage.SVCBIPv4Hint{
				Hint: ipv4,
			})
		}

		if len(ipv6) > 0 {
			newHttps.Value = append(newHttps.Value, &dnsmessage.SVCBIPv6Hint{
				Hint: ipv6,
			})
		}

		slog.Info("append ip hint to https", "value", newHttps.Value)

		msg.Answer[i] = newHttps
		break
	}
}
