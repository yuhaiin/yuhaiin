package resolver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"
	"unique"

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
	"golang.org/x/net/dns/dnsmessage"
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
	Msg() (dnsmessage.Message, error)
	Release()
}

type BytesResponse []byte

func (b BytesResponse) Msg() (msg dnsmessage.Message, err error) {
	if err := msg.Unpack(b); err != nil {
		return msg, err
	}

	return msg, nil
}

func (b BytesResponse) Release() { pool.PutBytes(b) }

type MsgResponse dnsmessage.Message

func (m MsgResponse) Msg() (msg dnsmessage.Message, err error) {
	return dnsmessage.Message(m), nil
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
	Name unique.Handle[string]
	Type dnsmessage.Type
}

func (c CacheKey) FromQuestion(q dnsmessage.Question) CacheKey {
	return CacheKey{
		// can save memory with netapi.Domain, so use rel domain
		Name: unique.Make(system.RelDomain(q.Name.String())),
		Type: q.Type,
	}
}

type client struct {
	edns0             dnsmessage.Resource
	dialer            Dialer
	rawStore          *lru.SyncLru[CacheKey, dnsmessage.Message]
	rawSingleflight   singleflight.GroupSync[dnsmessage.Question, dnsmessage.Message]
	refreshBackground syncmap.SyncMap[dnsmessage.Question, struct{}]
	config            Config
}

func NewClient(config Config, dialer Dialer) *client {
	var rh dnsmessage.ResourceHeader
	_ = rh.SetEDNS0(8192, dnsmessage.RCodeSuccess, false)

	optrbody := &dnsmessage.OPTResource{}
	if config.Subnet.IsValid() {
		// EDNS Subnet
		optionData := bytes.NewBuffer(nil)

		ip := config.Subnet.Masked().Addr()
		if ip.Is6() { // family https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
			optionData.Write([]byte{0b00000000, 0b00000010}) // family ipv6 2
		} else {
			optionData.Write([]byte{0b00000000, 0b00000001}) // family ipv4 1
		}

		mask := config.Subnet.Bits()
		optionData.WriteByte(byte(mask)) // mask
		optionData.WriteByte(0b00000000) // 0 In queries, it MUST be set to 0.

		var i int // cut the ip bytes
		if i = mask / 8; mask%8 != 0 {
			i++
		}

		optionData.Write(ip.AsSlice()[:i]) // subnet IP

		optrbody.Options = append(optrbody.Options, dnsmessage.Option{
			Code: 8,
			Data: optionData.Bytes(),
		})
	}

	c := &client{
		dialer: dialer,
		config: config,
		rawStore: lru.NewSyncLru(
			lru.WithCapacity[CacheKey, dnsmessage.Message](configuration.DNSCache),
			lru.WithDefaultTimeout[CacheKey, dnsmessage.Message](time.Second*600),
		),
		edns0: dnsmessage.Resource{
			Header: rh,
			Body:   optrbody,
		},
	}

	return c
}

func (c *client) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) ([]net.IP, error) {
	opt := &netapi.LookupIPOption{}

	for _, optf := range opts {
		optf(opt)
	}

	// only ipv6/ipv4
	switch opt.Mode {
	case netapi.ResolverModePreferIPv4:
		log.Debug("lookup ipv4 only", "domain", domain)
		return c.lookupIP(ctx, domain, dnsmessage.TypeA)
	case netapi.ResolverModePreferIPv6:
		log.Debug("lookup ipv6 only", "domain", domain)
		return c.lookupIP(ctx, domain, dnsmessage.TypeAAAA)
	}

	log.Debug("lookup ipv4 and ipv6", "domain", domain)

	aerr := make(chan error, 1)
	var a []net.IP

	go func() {
		var err error
		a, err = c.lookupIP(ctx, domain, dnsmessage.TypeA)
		aerr <- err
	}()

	resp, aaaaerr := c.lookupIP(ctx, domain, dnsmessage.TypeAAAA)

	if err := <-aerr; err != nil && aaaaerr != nil {
		return nil, mergerError(err, aaaaerr)
	}

	return append(resp, a...), nil
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

func (c *client) raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	dialer := c.dialer

	reqMsg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 uint16(rand.UintN(math.MaxUint16)),
			Response:           false,
			OpCode:             0,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   true,
			RecursionAvailable: false,
			RCode:              0,
		},
		Questions:   []dnsmessage.Question{req},
		Additionals: []dnsmessage.Resource{c.edns0},
	}

	buf := pool.GetBytes(8192)
	defer pool.PutBytes(buf)

	bytes, err := reqMsg.AppendPack(buf[:0])
	if err != nil {
		return dnsmessage.Message{}, err
	}

	request := &Request{
		QuestionBytes: bytes,
		Question:      req,
		ID:            reqMsg.ID,
	}

	var msg dnsmessage.Message

	for _, v := range []bool{false, true} {
		request.Truncated = v

		resp, err := dialer.Do(ctx, request)
		if err != nil {
			return dnsmessage.Message{}, err
		}
		defer resp.Release()

		if msg, err = resp.Msg(); err != nil {
			return dnsmessage.Message{}, err
		}

		if msg.ID != reqMsg.ID {
			return dnsmessage.Message{}, fmt.Errorf("id not match")
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
	if len(msg.Answers) > 0 {
		ttl = msg.Answers[0].Header.TTL
	}

	log.Select(slog.LevelDebug).PrintFunc("resolve domain", func() []any {
		args := []any{
			slog.String("resolver", c.config.Name),
			slog.Any("host", req.Name),
			slog.Any("type", req.Type),
			slog.Any("code", msg.RCode),
			slog.Any("ttl", ttl),
		}
		return args
	})

	if ttl > 1 {
		msg.Questions = nil
		c.rawStore.Add(CacheKey{}.FromQuestion(req), msg,
			lru.WithTimeout[CacheKey, dnsmessage.Message](time.Duration(ttl)*time.Second))
	}

	return msg, nil
}

func (c *client) Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	if !system.IsDomainName(req.Name.String()) {
		return dnsmessage.Message{}, fmt.Errorf("invalid domain: %s", req.Name.String())
	}

	if req.Class == 0 {
		req.Class = dnsmessage.ClassINET
	}

	msg, expired, ok := c.rawStore.LoadOptimistically(CacheKey{}.FromQuestion(req))
	if !ok {
		var err error
		msg, err, _ = c.rawSingleflight.Do(ctx, req, func(ctx context.Context) (dnsmessage.Message, error) { return c.raw(ctx, req) })
		if err != nil {
			return dnsmessage.Message{}, err
		}
	}

	msg.Questions = []dnsmessage.Question{req}

	if expired {
		if _, ok = c.refreshBackground.LoadOrStore(req, struct{}{}); !ok {
			// refresh expired response background
			go func() {
				defer c.refreshBackground.Delete(req)

				ctx = context.WithoutCancel(ctx)
				ctx, cancel := context.WithTimeout(ctx, configuration.ResolverTimeout)
				defer cancel()

				_, err := c.raw(ctx, req)
				if err != nil {
					log.Error("refresh domain background failed", "req", req, "err", err)
				}
			}()
		}
	}

	return cloneMessage(msg), nil
}

func (c *client) lookupIP(ctx context.Context, domain string, reqType dnsmessage.Type) ([]net.IP, error) {
	if len(domain) == 0 {
		return nil, fmt.Errorf("empty domain")
	}

	domain = system.AbsDomain(domain)

	name, err := dnsmessage.NewName(domain)
	if err != nil {
		return nil, fmt.Errorf("parse domain failed: %w", err)
	}

	msg, err := c.Raw(ctx, dnsmessage.Question{
		Name:  name,
		Type:  reqType,
		Class: dnsmessage.ClassINET,
	})
	if err != nil {
		return nil, fmt.Errorf("send dns message failed: %w", err)
	}

	if msg.Header.RCode != dnsmessage.RCodeSuccess {
		metrics.Counter.AddFailedDNS(domain, msg.Header.RCode, reqType)
		return nil, &net.DNSError{
			Err:         msg.Header.RCode.String(),
			Server:      c.config.Host,
			Name:        domain,
			IsNotFound:  true,
			IsTemporary: true,
		}
	}

	ips := make([]net.IP, 0, len(msg.Answers))

	for _, v := range msg.Answers {
		if v.Header.Type != reqType {
			continue
		}

		switch v.Header.Type {
		case dnsmessage.TypeA:
			ips = append(ips, net.IP(v.Body.(*dnsmessage.AResource).A[:]))
		case dnsmessage.TypeAAAA:
			ips = append(ips, net.IP(v.Body.(*dnsmessage.AAAAResource).AAAA[:]))
		}
	}

	if len(ips) == 0 {
		metrics.Counter.AddFailedDNS(domain, dnsmessage.RCodeSuccess, reqType)
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

func cloneMessage(msg dnsmessage.Message) dnsmessage.Message {
	n := dnsmessage.Message{
		Header:      msg.Header,
		Questions:   msg.Questions,
		Answers:     make([]dnsmessage.Resource, 0, len(msg.Answers)),
		Authorities: make([]dnsmessage.Resource, 0, len(msg.Authorities)),
		Additionals: make([]dnsmessage.Resource, 0, len(msg.Additionals)),
	}
	for _, a := range msg.Answers {
		n.Answers = append(n.Answers, dnsmessage.Resource{
			Header: a.Header,
			Body:   a.Body,
		})
	}
	for _, a := range msg.Authorities {
		n.Authorities = append(n.Authorities, dnsmessage.Resource{
			Header: a.Header,
			Body:   a.Body,
		})
	}
	for _, a := range msg.Additionals {
		n.Additionals = append(n.Additionals, dnsmessage.Resource{
			Header: a.Header,
			Body:   a.Body,
		})
	}
	return n
}
