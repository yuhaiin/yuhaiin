package dns

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"golang.org/x/net/dns/dnsmessage"
)

type dnsServer struct {
	server    string
	processor func(proxy.Address) dns.DNS
	listener  net.PacketConn
}

func NewDnsServer(server string, process func(proxy.Address) dns.DNS) server.Server {
	d := &dnsServer{server: server, processor: process}
	go func() {
		if err := d.start(); err != nil {
			log.Println(err)
		}
	}()

	return d
}

func (d *dnsServer) Close() error {
	if d.listener == nil {
		return nil
	}
	return d.listener.Close()
}

func (d *dnsServer) start() (err error) {
	d.listener, err = net.ListenPacket("udp", d.server)
	if err != nil {
		return fmt.Errorf("dns server listen failed: %w", err)
	}
	defer d.listener.Close()
	log.Println("new dns server listen at:", d.server)

	for {
		p := utils.GetBytes(utils.DefaultSize)
		n, addr, err := d.listener.ReadFrom(p)
		if err != nil {
			if e, ok := err.(net.Error); ok {
				if e.Temporary() {
					continue
				}
			}
			return fmt.Errorf("dns server read failed: %w", err)
		}

		go func(b []byte, n int, addr net.Addr, l net.PacketConn) {
			defer utils.PutBytes(b)

			var parse dnsmessage.Parser

			h, err := parse.Start(b[:n])
			if err != nil {
				log.Println(err)
				return
			}

			q, err := parse.Question()
			if err != nil {
				log.Println(err)
				return
			}

			add := proxy.ParseAddressSplit("", strings.TrimSuffix(q.Name.String(), "."), 0)
			ips, err := d.processor(add).LookupIP(strings.TrimSuffix(q.Name.String(), "."))
			if err != nil {
				log.Println(err)
			}

			resp := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:                 h.ID,
					Response:           true,
					Authoritative:      true,
					RecursionDesired:   true,
					RCode:              dnsmessage.RCodeSuccess,
					RecursionAvailable: true,
				},
				Questions: []dnsmessage.Question{
					{
						Name:  q.Name,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
				},
			}

			for _, ip := range ips {
				resource := dnsmessage.AResource{}
				copy(resource.A[:], ip)
				resp.Answers = append(resp.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  q.Name,
						Class: dnsmessage.ClassINET,
						TTL:   600,
					},
					Body: &resource,
				})
			}

			data, err := resp.Pack()
			if err != nil {
				log.Println(err)
				return
			}

			l.WriteTo(data, addr)
		}(p, n, addr, d.listener)
	}

}
