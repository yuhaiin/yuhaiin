package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"golang.org/x/net/dns/dnsmessage"
)

type dnsServer struct {
	server      string
	resolver    dns.DNS
	listener    net.PacketConn
	tcpListener net.Listener
}

func NewDnsServer(server string, process dns.DNS) server.DNSServer {
	d := &dnsServer{server: server, resolver: process}

	if server == "" {
		log.Warningln("dns server is empty, skip to listen tcp and udp")
		return d
	}

	go func() {
		if err := d.start(); err != nil {
			log.Errorln(err)
		}
	}()

	go func() {
		if err := d.startTCP(); err != nil {
			log.Errorln(err)
		}
	}()

	return d
}

func (d *dnsServer) Close() error {
	if d.listener != nil {
		d.listener.Close()
	}
	if d.tcpListener != nil {
		d.tcpListener.Close()
	}

	return nil
}

func (d *dnsServer) start() (err error) {
	d.listener, err = dialer.ListenPacket("udp", d.server)
	if err != nil {
		return fmt.Errorf("dns udp server listen failed: %w", err)
	}
	defer d.listener.Close()
	log.Infoln("new udp dns server listen at:", d.server)

	for {
		buf := pool.GetBytes(nat.MaxSegmentSize)

		n, addr, err := d.listener.ReadFrom(buf)
		if err != nil {
			if e, ok := err.(net.Error); ok {
				if e.Temporary() {
					continue
				}
			}
			return fmt.Errorf("dns udp server handle failed: %w", err)
		}

		go func() {
			defer pool.PutBytes(buf)
			data, err := d.handle(buf[:n])
			if err != nil {
				log.Errorln("dns server handle data failed:", err)
				return
			}

			if _, err = d.listener.WriteTo(data, addr); err != nil {
				log.Errorln(err)
			}
		}()
	}
}

func (d *dnsServer) startTCP() (err error) {
	d.tcpListener, err = net.Listen("tcp", d.server)
	if err != nil {
		return fmt.Errorf("dns tcp server listen failed: %w", err)
	}
	defer d.tcpListener.Close()
	log.Errorln("new tcp dns server listen at:", d.server)
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

		go func() {
			defer conn.Close()
			if err := d.HandleTCP(conn); err != nil {
				log.Errorln(err)
			}
		}()
	}
}

func (d *dnsServer) HandleTCP(c net.Conn) error {
	var length uint16
	if err := binary.Read(c, binary.BigEndian, &length); err != nil {
		return fmt.Errorf("read dns length failed: %w", err)
	}

	data := pool.GetBytes(int(length))
	defer pool.PutBytes(data)

	n, err := io.ReadFull(c, data[:length])
	if err != nil {
		return fmt.Errorf("dns server read data failed: %w", err)
	}

	data, err = d.handle(data[:n])
	if err != nil {
		return fmt.Errorf("dns server handle failed: %w", err)
	}

	if err = binary.Write(c, binary.BigEndian, uint16(len(data))); err != nil {
		return fmt.Errorf("dns server write length failed: %w", err)
	}
	_, err = c.Write(data)
	return err
}

func (d *dnsServer) HandleUDP(l net.PacketConn) error {
	p := pool.GetBytes(nat.MaxSegmentSize)
	defer pool.PutBytes(p)
	n, addr, err := l.ReadFrom(p)
	if err != nil {
		return err
	}

	data, err := d.handle(p[:n])
	if err != nil {
		return fmt.Errorf("dns server handle failed: %w", err)
	}
	_, err = l.WriteTo(data, addr)
	return err
}

func (d *dnsServer) Do(b []byte) ([]byte, error) { return d.handle(b) }

func (d *dnsServer) handle(b []byte) ([]byte, error) {
	var parse dnsmessage.Parser

	h, err := parse.Start(b)
	if err != nil {
		return nil, fmt.Errorf("dns server parse failed: %w", err)
	}

	q, err := parse.Question()
	if err != nil {
		return nil, fmt.Errorf("dns server parse failed: %w", err)
	}

	add := strings.TrimSuffix(q.Name.String(), ".")

	if q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA &&
		q.Type != dnsmessage.TypePTR {
		log.Debugln(q.Type, "not a, aaaa or ptr")
		return d.resolver.Do(add, b)
	}

	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 h.ID,
			Response:           true,
			Authoritative:      false,
			RecursionDesired:   false,
			RCode:              dnsmessage.RCodeSuccess,
			RecursionAvailable: false,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  q.Name,
				Type:  q.Type,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	// PTR
	if q.Type == dnsmessage.TypePTR {
		return d.handlePtr(add, b, resp, d.resolver, q.Name)
	}

	// A or AAAA
	r, err := d.resolver.Record(add, q.Type)
	if err != nil {
		if !errors.Is(err, ErrNoIPFound) && !errors.Is(err, ErrCondEmptyResponse) {
			if errors.Is(err, proxy.ErrBlocked) {
				log.Debugln(err)
			} else {
				log.Errorf("lookup domain %s failed: %v\n", q.Name.String(), err)
			}
		}

		if !errors.Is(err, ErrNoIPFound) {
			resp.RCode = dnsmessage.RCodeNameError
		}
	}

	for _, a := range r.IPs {
		var resource dnsmessage.ResourceBody
		if q.Type == dnsmessage.TypeA {
			rr := &dnsmessage.AResource{}
			copy(rr.A[:], a.To4())
			resource = rr
		} else {
			rr := &dnsmessage.AAAAResource{}
			copy(rr.AAAA[:], a.To16())
			resource = rr
		}
		resp.Answers = append(resp.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  q.Name,
				Type:  q.Type,
				Class: dnsmessage.ClassINET,
				TTL:   r.TTL,
			},
			Body: resource,
		})
	}

	return resp.Pack()
}

func (d *dnsServer) handlePtr(address string, raw []byte, msg dnsmessage.Message,
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

	return processor.Do(address, raw)
}
