package dns

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

type DNS interface {
	LookupIP(domain string) ([]net.IP, error)
	Resolver() *net.Resolver
}

var DefaultDNS DNS = &systemDNS{}

type systemDNS struct{}

func (d *systemDNS) LookupIP(domain string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(context.TODO(), "ip", domain)
}
func (d *systemDNS) Resolver() *net.Resolver { return net.DefaultResolver }

type client struct {
	template dnsmessage.Message
	send     func([]byte) ([]byte, error)
}

func NewClient(subnet *net.IPNet, send func([]byte) ([]byte, error)) *client {
	c := &client{
		send: send,
		template: dnsmessage.Message{
			Header: dnsmessage.Header{
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
					Name:  dnsmessage.MustNewName("."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
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

		c.template.Additionals = append(c.template.Additionals, dnsmessage.Resource{
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
	return c
}

func (c *client) Request(domain string) ([]net.IP, error) {
	req := c.template
	req.ID = uint16(rand.Intn(65535))
	req.Questions[0].Name = dnsmessage.MustNewName(domain + ".")
	d, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack dns message failed: %w", err)
	}

	d, err = c.send(d)
	if err != nil {
		return nil, fmt.Errorf("send dns message failed: %w", err)
	}

	var p dnsmessage.Parser
	he, err := p.Start(d)
	if err != nil {
		return nil, err
	}

	if he.ID != req.ID {
		return nil, fmt.Errorf("id not match")
	}

	p.SkipAllQuestions()

	i := make([]net.IP, 0, 1)
	for {
		a, err := p.Answer()
		if err == dnsmessage.ErrSectionDone {
			if len(i) == 0 {
				return nil, fmt.Errorf("no answer")
			}
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
}
