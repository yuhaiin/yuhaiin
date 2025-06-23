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
	"slices"
	"sync"
	"time"
	"unsafe"

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
	Name string
	Type dnsmessage.Type
}

func CacheKeyFromQuestion(q dnsmessage.Question, unsafeC bool) CacheKey {
	var name string
	if unsafeC {
		name = unsafe.String(unsafe.SliceData(q.Name.Data[:q.Name.Length]), q.Name.Length)
	} else {
		name = q.Name.String()
	}

	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}

	return CacheKey{
		Name: name,
		Type: q.Type,
	}
}

type client struct {
	edns0             dnsmessage.Resource
	dialer            Dialer
	rawStore          *lru.SyncLru[CacheKey, *rawEntry]
	rawSingleflight   singleflight.GroupSync[dnsmessage.Question, *rawEntry]
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
			lru.WithCapacity[CacheKey, *rawEntry](configuration.DNSCache),
			lru.WithDefaultTimeout[CacheKey, *rawEntry](time.Second*600),
		),
		edns0: dnsmessage.Resource{
			Header: rh,
			Body:   optrbody,
		},
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
		ips, err := c.lookupIP(ctx, domain, dnsmessage.TypeA)
		return &netapi.IPs{A: ips}, err
	case netapi.ResolverModePreferIPv6:
		log.Debug("lookup ipv6 only", "domain", domain)
		ips, err := c.lookupIP(ctx, domain, dnsmessage.TypeAAAA)
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
		a, aerr = c.lookupIP(ctx, domain, dnsmessage.TypeA)
	}()

	resp, aaaaerr := c.lookupIP(ctx, domain, dnsmessage.TypeAAAA)

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

func (c *client) query(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
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

	if req.Type == TypeHTTPS {
		// remove ip hint, make safari use fakeip instead of ip hint
		for _, v := range removeIPHint(req.Name, msg) {
			if len(v) == 0 {
				continue
			}

			req := dnsmessage.Question{
				Name:  req.Name,
				Type:  v[0].Header.Type,
				Class: dnsmessage.ClassINET,
			}

			c.rawStore.Add(CacheKeyFromQuestion(req, false),
				newRawEntry(dnsmessage.Message{
					Header: dnsmessage.Header{
						ID:                 0,
						Response:           true,
						OpCode:             0,
						Authoritative:      false,
						Truncated:          false,
						RecursionDesired:   true,
						RecursionAvailable: true,
						RCode:              dnsmessage.RCodeSuccess,
					},
					Questions: []dnsmessage.Question{req},
					Answers:   v,
				}),
				lru.WithTimeout[CacheKey, *rawEntry](time.Duration(ttl)*time.Second),
			)
		}
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
		c.rawStore.Add(CacheKeyFromQuestion(req, false), newRawEntry(msg),
			lru.WithTimeout[CacheKey, *rawEntry](time.Duration(ttl)*time.Second))
	}

	return msg, nil
}

func (c *client) Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	rawmsg, err := c.raw(ctx, req)
	if err != nil {
		return dnsmessage.Message{}, err
	}

	msg := rawmsg.Message()

	msg.Questions = []dnsmessage.Question{req}

	// TODO deep copy resource.Body
	msg.Answers = slices.Clone(msg.Answers)
	msg.Authorities = slices.Clone(msg.Authorities)
	msg.Additionals = slices.Clone(msg.Additionals)

	return msg, nil
}

func (c *client) raw(ctx context.Context, req dnsmessage.Question) (*rawEntry, error) {
	if !system.IsDomainName(unsafe.String(unsafe.SliceData(req.Name.Data[:req.Name.Length]), req.Name.Length)) {
		return nil, fmt.Errorf("invalid domain: %s", req.Name.String())
	}

	if req.Class == 0 {
		req.Class = dnsmessage.ClassINET
	}

	rawmsg, expired, ok := c.rawStore.LoadOptimistically(CacheKeyFromQuestion(req, true))
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

	name, err := dnsmessage.NewName(domain)
	if err != nil {
		return nil, fmt.Errorf("parse domain failed: %w", err)
	}

	rawmsg, err := c.raw(ctx, dnsmessage.Question{
		Name:  name,
		Type:  reqType,
		Class: dnsmessage.ClassINET,
	})
	if err != nil {
		return nil, fmt.Errorf("send dns message failed: %w", err)
	}

	if rawmsg.RCode() != dnsmessage.RCodeSuccess {
		metrics.Counter.AddFailedDNS(domain, rawmsg.RCode(), reqType)
		return nil, &net.DNSError{
			Err:         rawmsg.RCode().String(),
			Server:      c.config.Host,
			Name:        domain,
			IsNotFound:  true,
			IsTemporary: true,
		}
	}

	var ips []net.IP

	switch reqType {
	case dnsmessage.TypeA:
		ips = rawmsg.A()
	case dnsmessage.TypeAAAA:
		ips = rawmsg.AAAA()
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

type rawEntry struct {
	mu   sync.RWMutex
	msg  dnsmessage.Message
	ipv4 []net.IP
	ipv6 []net.IP
}

func newRawEntry(msg dnsmessage.Message) *rawEntry {
	return &rawEntry{
		msg: msg,
	}
}

func (r *rawEntry) Message() dnsmessage.Message {
	return r.msg
}

func (r *rawEntry) RCode() dnsmessage.RCode {
	return r.msg.RCode
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

	r.ipv4 = make([]net.IP, 0, len(r.msg.Answers))

	for _, v := range r.msg.Answers {
		if v.Header.Type != dnsmessage.TypeA {
			continue
		}

		r.ipv4 = append(r.ipv4, net.IP(v.Body.(*dnsmessage.AResource).A[:]))
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

	r.ipv6 = make([]net.IP, 0, len(r.msg.Answers))

	for _, v := range r.msg.Answers {
		if v.Header.Type != dnsmessage.TypeAAAA {
			continue
		}

		r.ipv6 = append(r.ipv6, net.IP(v.Body.(*dnsmessage.AAAAResource).AAAA[:]))
	}

	return r.ipv6
}

func removeIPHint(name dnsmessage.Name, msg dnsmessage.Message) [][]dnsmessage.Resource {
	var ipHints [][]dnsmessage.Resource
	for _, v := range msg.Answers {
		if v.Header.Type != TypeHTTPS {
			continue
		}

		unknownResource, ok := v.Body.(*dnsmessage.UnknownResource)
		if !ok {
			slog.Error("is not unknown resource skip", "type", v.Header.Type)
			continue
		}

		if unknownResource.Type != TypeHTTPS {
			continue
		}

		unknownResource.Data, ipHints = removeIPHintFromResource(name, unknownResource.Data, v.Header.TTL)
	}

	return ipHints
}

func removeIPHintFromResource(name dnsmessage.Name, msg []byte, ttl uint32) (result []byte, ipHint [][]dnsmessage.Resource) {
	endOff := len(msg)
	_, off, err := unpackUint16(msg, 0)
	if err != nil {
		return msg, nil
	}

	if off, err = skipName(msg, off); err != nil {
		return msg, nil
	}

	type remove struct {
		start int
		end   int
	}

	var removes []remove
	var ipHints [][]dnsmessage.Resource

	for off < endOff {
		start := off

		var err error
		var k uint16
		k, off, err = unpackUint16(msg, off)
		if err != nil {
			return msg, nil
		}
		var l uint16
		l, off, err = unpackUint16(msg, off)
		if err != nil {
			return msg, nil
		}
		off += int(l)

		end := off

		if ParamKey(k) == ParamIPv4Hint || ParamKey(k) == ParamIPv6Hint {
			ips := splitIpHint(msg[start+4:end], ParamKey(k) == ParamIPv6Hint)
			slog.Info("remove ip hint",
				"name", name.String(),
				"key", ParamKey(k),
				"value", ips,
				"length", len(msg[start:end]),
			)
			hints := make([]dnsmessage.Resource, 0, len(ips))
			for _, v := range ips {
				resource := dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  name,
						Class: dnsmessage.ClassINET,
						TTL:   ttl,
					},
				}
				if ParamKey(k) == ParamIPv6Hint {
					resource.Body = &dnsmessage.AAAAResource{AAAA: [16]byte(v)}
					resource.Header.Type = dnsmessage.TypeAAAA
				} else {
					resource.Body = &dnsmessage.AResource{A: [4]byte(v)}
					resource.Header.Type = dnsmessage.TypeA
				}

				hints = append(hints, resource)
			}

			removes = append(removes, remove{start, end})
			if len(hints) > 0 {
				ipHints = append(ipHints, hints)
			}
		}
	}

	if len(removes) == 0 {
		return msg, ipHints
	}

	lastEnd := -1
	length := 0

	for _, v := range removes {
		if lastEnd == -1 {
			lastEnd = v.end
			length = v.start
			continue
		}

		n := copy(msg[length:], msg[lastEnd:v.start])
		length += n
		lastEnd = v.end
	}

	length += copy(msg[length:], msg[lastEnd:])

	return msg[:length], ipHints
}

func splitIpHint(msg []byte, v6 bool) []net.IP {
	start := 0
	end := len(msg)

	size := 4
	if v6 {
		size = 16
	}

	resp := make([]net.IP, 0, len(msg)/size)
	for start < end {
		resp = append(resp, net.IP(msg[start:start+size]))
		start += size
	}

	return resp
}
