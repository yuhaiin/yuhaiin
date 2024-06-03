package dns

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
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/singleflight"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"golang.org/x/net/dns/dnsmessage"
)

type Config struct {
	Type       pd.Type
	Subnet     netip.Prefix
	Name       string
	Host       string
	Servername string
	Dialer     netapi.Proxy
}

var dnsMap syncmap.SyncMap[pd.Type, func(Config) (netapi.Resolver, error)]

func New(config Config) (netapi.Resolver, error) {
	f, ok := dnsMap.Load(config.Type)
	if !ok {
		return nil, fmt.Errorf("no dns type %v process found", config.Type)
	}

	if config.Dialer == nil {
		config.Dialer = direct.Default
	}
	return f(config)
}

func Register(tYPE pd.Type, f func(Config) (netapi.Resolver, error)) {
	if f != nil {
		dnsMap.Store(tYPE, f)
	}
}

var _ netapi.Resolver = (*client)(nil)

type request struct {
	Truncated bool
	Question  []byte
}

type client struct {
	do              func(context.Context, *request) ([]byte, error)
	config          Config
	edns0           dnsmessage.Resource
	rawStore        *lru.LRU[dnsmessage.Question, dnsmessage.Message]
	rawSingleflight singleflight.Group[dnsmessage.Question, dnsmessage.Message]
}

func NewClient(config Config, do func(context.Context, *request) ([]byte, error)) *client {
	var rh dnsmessage.ResourceHeader
	_ = rh.SetEDNS0(nat.MaxSegmentSize, dnsmessage.RCodeSuccess, false)

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

	return &client{
		do:       do,
		config:   config,
		rawStore: lru.New(lru.WithCapacity[dnsmessage.Question, dnsmessage.Message](configuration.DNSCache)),
		edns0: dnsmessage.Resource{
			Header: rh,
			Body:   optrbody,
		},
	}
}

func (c *client) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) ([]net.IP, error) {

	opt := &netapi.LookupIPOption{
		A: true,
	}

	for _, optf := range opts {
		optf(opt)
	}

	// only ipv6
	if opt.AAAA && !opt.A {
		return c.lookupIP(ctx, domain, dnsmessage.TypeAAAA)
	}

	// only ipv4
	if opt.A && !opt.AAAA {
		return c.lookupIP(ctx, domain, dnsmessage.TypeA)
	}

	aaaaerr := make(chan error, 1)
	var aaaa []net.IP

	go func() {
		var err error
		aaaa, err = c.lookupIP(ctx, domain, dnsmessage.TypeAAAA)
		if err != nil {
			aaaaerr <- fmt.Errorf("lookup ipv6 failed: %w", err)
		} else {
			aaaaerr <- nil
		}
	}()

	resp, aerr := c.lookupIP(ctx, domain, dnsmessage.TypeA)

	if err := <-aaaaerr; err != nil && aerr != nil {
		return nil, errors.Join(err, fmt.Errorf("lookup ipv4 failed: %w", aerr))
	}

	return append(resp, aaaa...), nil
}

func (c *client) Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	if req.Class == 0 {
		req.Class = dnsmessage.ClassINET
	}

	msg, ok := c.rawStore.Load(req)
	if ok {
		return msg, nil
	}

	msg, err, _ := c.rawSingleflight.Do(req, func() (dnsmessage.Message, error) {
		send := c.do

		if send == nil {
			return dnsmessage.Message{}, fmt.Errorf("no dns process function")
		}

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

		buf := pool.GetBytes(nat.MaxSegmentSize)
		defer pool.PutBytes(buf)

		bytes, err := reqMsg.AppendPack(buf[:0])
		if err != nil {
			return dnsmessage.Message{}, err
		}

		request := &request{Question: bytes}

		for _, v := range []bool{false, true} {
			request.Truncated = v

			resp, err := send(ctx, request)
			if err != nil {
				return dnsmessage.Message{}, err
			}
			defer pool.PutBytes(resp)

			if err = msg.Unpack(resp); err != nil {
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
			log.Info("resolve domain retry by Truncated", "domain", req.Name, "type", req.Type)
		}

		ttl := uint32(600)
		if len(msg.Answers) > 0 {
			ttl = msg.Answers[0].Header.TTL
		}

		args := []any{
			slog.String("resolver", c.config.Name),
			slog.Any("host", req.Name),
			slog.Any("type", req.Type),
			slog.Any("code", msg.RCode),
			slog.Any("ttl", ttl),
		}

		log.Debug("resolve domain", args...)

		if ttl > 1 {
			c.rawStore.Add(req, msg,
				lru.WithExpireTimeUnix(time.Now().Add(time.Duration(ttl)*time.Second)))
		}

		return msg, nil
	})

	return msg, err
}

func (c *client) lookupIP(ctx context.Context, domain string, reqType dnsmessage.Type) ([]net.IP, error) {
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}

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
		return nil, netapi.NewDNSErrCode(msg.Header.RCode)
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
		return nil, netapi.NewDNSErrCode(dnsmessage.RCodeSuccess)
	}

	return ips, nil
}

func (c *client) Close() error { return nil }
