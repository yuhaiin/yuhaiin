package dns

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"golang.org/x/net/dns/dnsmessage"
)

type DNS interface {
	LookupIP(domain string) ([]net.IP, error)
	Resolver() *net.Resolver
}

func reqAndHandle(domain string, subnet *net.IPNet, f func([]byte) ([]byte, error)) ([]net.IP, error) {
	// var req []byte
	// if subnet == nil {
	// 	req = creatRequest(domain, A, false)
	// } else {
	// 	req = createEDNSReq(domain, A, createEdnsClientSubnet(subnet))
	// }

	m := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 uint16(rand.Intn(65536)),
			Response:           false,
			OpCode:             0,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   true,
			RecursionAvailable: false,
			RCode:              0,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(domain + "."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	if subnet != nil {
		optionData := bytes.NewBuffer(nil)
		mask, _ := subnet.Mask.Size()
		ip := subnet.IP.To4()
		if ip == nil { // family https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
			optionData.Write([]byte{0b00000000, 0b00000010}) // family ipv6 2
			ip = subnet.IP.To16()
		} else {
			optionData.Write([]byte{0b00000000, 0b00000001}) // family ipv4 1
		}
		optionData.WriteByte(byte(mask)) // mask
		optionData.WriteByte(0b00000000) // 0 In queries, it MUST be set to 0.
		optionData.Write(ip)             // subnet IP

		m.Additionals = append(m.Additionals, dnsmessage.Resource{
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
		})
	}
	req, err := m.Pack()
	if err != nil {
		return nil, err
	}
	// fmt.Println(req)
	b, err := f(req)
	if err != nil {
		return nil, err
	}

	var p dnsmessage.Parser
	he, err := p.Start(b)
	if err != nil {
		return nil, err
	}

	if he.ID != m.ID {
		return nil, fmt.Errorf("id not match")
	}

	p.SkipAllQuestions()

	i := make([]net.IP, 0, 1)
	for {
		a, err := p.Answer()
		if err == dnsmessage.ErrSectionDone {
			return i, nil
		}
		if err != nil {
			return nil, err
		}
		if a.Header.Type != dnsmessage.TypeA {
			continue
		}

		A := a.Body.(*dnsmessage.AResource).A
		i = append(i, net.IPv4(A[0], A[1], A[2], A[3]))
	}
	// fmt.Println(p.AllAnswers())
	// return Resolve(req, b)
}

var _ DNS = (*dns)(nil)

type dns struct {
	DNS
	Server string
	Subnet *net.IPNet
	cache  *utils.LRU
	proxy  proxy.Proxy
}

func NewDNS(host string, subnet *net.IPNet, p proxy.Proxy) DNS {
	if p == nil {
		p = &proxy.DefaultProxy{}
	}

	_, _, err := net.SplitHostPort(host)
	if e, ok := err.(*net.AddrError); ok {
		if strings.Contains(e.Err, "missing port in address") {
			host = net.JoinHostPort(host, "53")
		}
	}

	return &dns{
		Server: host,
		Subnet: subnet,
		cache:  utils.NewLru(200, 20*time.Minute),
		proxy:  p,
	}
}

// LookupIP resolve domain return net.IP array
func (n *dns) LookupIP(domain string) (DNS []net.IP, err error) {
	if x, _ := n.cache.Load(domain); x != nil {
		return x.([]net.IP), nil
	}
	DNS, err = reqAndHandle(domain, n.Subnet, n.udp)
	if err != nil || len(DNS) == 0 {
		return nil, fmt.Errorf("normal resolve domain %s failed: %v", domain, err)
	}
	n.cache.Add(domain, DNS)
	return
}

func (n *dns) Resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.DialTimeout("udp", n.Server, time.Second*6)
		},
	}
}

func (n *dns) udp(req []byte) (data []byte, err error) {
	var b = utils.GetBytes(utils.DefaultSize)
	defer utils.PutBytes(utils.DefaultSize, &(b))

	addr, err := net.ResolveUDPAddr("udp", n.Server)
	if err != nil {
		return nil, fmt.Errorf("resolve addr failed: %v", err)
	}

	conn, err := n.proxy.PacketConn(n.Server)
	if err != nil {
		return nil, fmt.Errorf("get packetConn failed: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = conn.WriteTo(req, addr)
	if err != nil {
		return nil, err
	}

	nn, _, err := conn.ReadFrom(b)
	return b[:nn], err
}
