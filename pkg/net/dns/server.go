package dns

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"golang.org/x/net/dns/dnsmessage"
)

type DNSServer struct {
	server      string
	processor   func(proxy.Address) dns.DNS
	listener    net.PacketConn
	tcpListener net.Listener
}

func NewDnsServer(server string, process func(proxy.Address) dns.DNS) *DNSServer {
	d := &DNSServer{server: server, processor: process}
	go func() {
		if err := d.start(); err != nil {
			log.Println(err)
		}
	}()

	go func() {
		if err := d.startTCP(); err != nil {
			log.Println(err)
		}
	}()

	return d
}

func (d *DNSServer) Close() error {
	if d.listener != nil {
		d.listener.Close()
	}
	if d.tcpListener != nil {
		d.tcpListener.Close()
	}

	return nil
}

func (d *DNSServer) start() (err error) {
	d.listener, err = net.ListenPacket("udp", d.server)
	if err != nil {
		return fmt.Errorf("dns udp server listen failed: %w", err)
	}
	defer d.listener.Close()
	log.Println("new udp dns server listen at:", d.server)

	for {

		err = d.HandleUDP(d.listener)
		if err != nil {
			log.Println(err)
			return err
		}
	}

}

func (d *DNSServer) startTCP() (err error) {
	d.tcpListener, err = net.Listen("tcp", d.server)
	if err != nil {
		return fmt.Errorf("dns server listen failed: %w", err)
	}
	log.Println("new tcp dns server listen at:", d.server)
	for {
		conn, err := d.tcpListener.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok {
				if e.Temporary() {
					continue
				}
			}
			return fmt.Errorf("dns server accept failed: %w", err)
		}

		go d.HandleTCP(conn)
	}
}

func (d *DNSServer) HandleTCP(c net.Conn) {
	defer c.Close()
	l := make([]byte, 2)
	_, err := io.ReadFull(c, l)
	if err != nil {
		log.Println(err)
		return
	}

	length := int(binary.BigEndian.Uint16(l))
	data := utils.GetBytes(length)
	defer utils.PutBytes(data)

	n, err := io.ReadFull(c, data[:length])
	if err != nil {
		log.Println(err)
		return
	}

	data, err = d.handle(data[:n])
	if err != nil {
		log.Println(err)
		return
	}

	binary.Write(c, binary.BigEndian, uint16(len(data)))
	c.Write(data)
}

func (d *DNSServer) HandleUDP(l net.PacketConn) error {
	p := utils.GetBytes(utils.DefaultSize)
	defer utils.PutBytes(p)
	n, addr, err := l.ReadFrom(p)
	if err != nil {
		if e, ok := err.(net.Error); ok {
			if e.Temporary() {
				return nil
			}
		}
		return fmt.Errorf("dns server read failed: %w", err)
	}

	data, err := d.handle(p[:n])
	if err != nil {
		log.Println(err)
		return nil
	}
	l.WriteTo(data, addr)

	return nil
}

var emptyIPResponse = dns.NewIPResponse(nil, 0)

func (d *DNSServer) handle(b []byte) ([]byte, error) {
	var parse dnsmessage.Parser

	h, err := parse.Start(b)
	if err != nil {
		return nil, fmt.Errorf("dns server parse failed: %w", err)
	}

	q, err := parse.Question()
	if err != nil {
		return nil, fmt.Errorf("dns server parse failed: %w", err)
	}

	add := proxy.ParseAddressSplit("", strings.TrimSuffix(q.Name.String(), "."), 0)

	if q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA &&
		q.Type != dnsmessage.TypePTR {
		log.Println(q.Type, "not a, aaaa or ptr")
		return d.processor(add).Do(b)
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
				Type:  q.Type,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	processor := d.processor(add)

	// PTR
	if q.Type == dnsmessage.TypePTR {
		return d.handlePtr(b, resp, processor, q.Name)
	}

	// A or AAAA
	r, err := processor.LookupIP(strings.TrimSuffix(q.Name.String(), "."))
	if err != nil {
		log.Printf("lookup domain %s failed: %v\n", q.Name.String(), err)
		resp.RCode = dnsmessage.RCodeNameError
		r = emptyIPResponse
	}

	for _, ip := range r.IPs() {
		resource := dnsmessage.AResource{}
		copy(resource.A[:], ip)
		resp.Answers = append(resp.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  q.Name,
				Class: dnsmessage.ClassINET,
				TTL:   r.TTL(),
			},
			Body: &resource,
		})
	}

	return resp.Pack()
}

func (d *DNSServer) handlePtr(raw []byte, msg dnsmessage.Message,
	processor dns.DNS, name dnsmessage.Name) ([]byte, error) {
	if ff, ok := processor.(interface{ LookupPtr(string) (string, error) }); ok {
		r, err := ff.LookupPtr(name.String())
		if err == nil {
			msg.Answers = []dnsmessage.Resource{
				{
					Header: dnsmessage.ResourceHeader{
						Name:  name,
						Class: dnsmessage.ClassINET,
						TTL:   600,
					},
					Body: &dnsmessage.PTRResource{
						PTR: dnsmessage.MustNewName(r + "."),
					},
				},
			}

			return msg.Pack()
		}
	}

	return processor.Do(raw)
}
