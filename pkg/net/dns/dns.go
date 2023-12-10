package dns

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
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
	IPv6       bool
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

type client struct {
	send            func(context.Context, []byte) ([]byte, error)
	config          Config
	subnet          []dnsmessage.Resource
	rawStore        *lru.LRU[Req, dnsmessage.Message]
	rawSingleflight singleflight.Group[Req, dnsmessage.Message]
}

func NewClient(config Config, send func(context.Context, []byte) ([]byte, error)) *client {
	c := &client{
		send:     send,
		config:   config,
		rawStore: lru.NewLru(lru.WithCapacity[Req, dnsmessage.Message](1024)),
	}

	if !config.Subnet.IsValid() {
		return c
	}

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

	c.subnet = []dnsmessage.Resource{
		{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("."),
				Type:  41,
				Class: 4096,
				TTL:   0,
			},
			Body: &dnsmessage.OPTResource{
				Options: []dnsmessage.Option{
					{
						Code: 8,
						Data: optionData.Bytes(),
					},
				},
			},
		},
	}
	return c
}

func (c *client) LookupIP(ctx context.Context, domain string) ([]net.IP, error) {
	var aaaaerr error
	var aaaa []net.IP
	var wg sync.WaitGroup

	if c.config.IPv6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			aaaa, aaaaerr = c.lookupIP(ctx, domain, dnsmessage.TypeAAAA)
		}()
	}

	resp, aerr := c.lookupIP(ctx, domain, dnsmessage.TypeA)

	if c.config.IPv6 {
		wg.Wait()
		if aaaaerr == nil {
			resp = append(resp, aaaa...)
		}
	}

	if aerr != nil && (!c.config.IPv6 || aaaaerr != nil) {
		return nil, fmt.Errorf("lookup ip failed: aaaa: %w, a: %w", aaaaerr, aerr)
	}

	return resp, nil
}

type Req struct {
	Name dnsmessage.Name
	Type dnsmessage.Type
}

func (c *client) Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	key := Req{Name: req.Name, Type: req.Type}

	msg, ok := c.rawStore.Load(key)
	if ok {
		return msg, nil
	}

	msg, err, _ := c.rawSingleflight.Do(key, func() (dnsmessage.Message, error) {
		send := c.send

		if send == nil {
			return dnsmessage.Message{}, fmt.Errorf("no dns process function")
		}

		reqMsg := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:                 uint16(rand.Intn(math.MaxUint16)),
				Response:           false,
				OpCode:             0,
				Authoritative:      false,
				Truncated:          false,
				RecursionDesired:   true,
				RecursionAvailable: false,
				RCode:              0,
			},
			Questions:   []dnsmessage.Question{req},
			Additionals: c.subnet,
		}

		buf := pool.GetBytes(pool.DefaultSize)
		defer pool.PutBytes(buf)

		bytes, err := reqMsg.AppendPack(buf[:0])
		if err != nil {
			return dnsmessage.Message{}, err
		}

		resp, err := send(ctx, bytes)
		if err != nil {
			return dnsmessage.Message{}, err
		}

		if err = msg.Unpack(resp); err != nil {
			return dnsmessage.Message{}, err
		}

		if msg.ID != reqMsg.ID {
			return dnsmessage.Message{}, fmt.Errorf("id not match")
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

		c.rawStore.Add(key, msg, lru.WithExpireTimeUnix(time.Now().Add(time.Duration(ttl)*time.Second)))

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
		return nil, &dnsErrCode{code: msg.Header.RCode}
	}

	ips := make([]net.IP, 0, len(msg.Answers))

	for _, v := range msg.Answers {
		switch x := v.Body.(type) {
		case *dnsmessage.AResource:
			if reqType == dnsmessage.TypeA {
				ips = append(ips, net.IP(x.A[:]))
			}
		case *dnsmessage.AAAAResource:
			if reqType == dnsmessage.TypeAAAA {
				ips = append(ips, net.IP(x.AAAA[:]))
			}
		}
	}

	if len(ips) == 0 {
		return nil, &dnsErrCode{code: dnsmessage.RCodeSuccess}
	}

	return ips, nil
}

func (c *client) Close() error { return nil }

type dnsErrCode struct {
	code dnsmessage.RCode
}

func (d dnsErrCode) Error() string {
	return d.code.String()
}

func (d *dnsErrCode) As(err any) bool {
	dd, ok := err.(*dnsErrCode)

	dd.code = d.code

	return ok
}
