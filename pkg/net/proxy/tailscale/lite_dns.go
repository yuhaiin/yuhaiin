package tailscale

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"

	"codeberg.org/miekg/dns"
	lite "github.com/yuhaiin/tailscale-lite"
)

// Fail closed on queries outside the authenticated MagicDNS name table.
// An unknown name must not silently escape through the host resolver.
var errTailscaleDNSUnavailable = errors.New("tailscale: MagicDNS unavailable")

func liteDNSQuery(ctx context.Context, client *lite.Client, request []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil { return nil, err }
	if client == nil { return nil, errTailscaleDNSUnavailable }
	var q dns.Msg
	if err := q.Unpack(request); err != nil { return nil, err }
	var reply dns.Msg
	reply.SetReply(&q)
	reply.Authoritative = true
	if len(q.Question) != 1 || q.Opcode != dns.OpcodeQuery {
		reply.Rcode = dns.RcodeFormatError
		return reply.Pack()
	}
	question := q.Question[0]
	if question.Qclass != dns.ClassINET {
		reply.Rcode = dns.RcodeRefused
		return reply.Pack()
	}
	ips, owned := client.LookupIP(question.Name)
	if !owned {
		reply.Rcode = dns.RcodeRefused
		return reply.Pack()
	}
	if len(ips) == 0 {
		reply.Rcode = dns.RcodeNameError
		return reply.Pack()
	}
	for _, ip := range ips {
		switch {
		case ip.Is4() && question.Qtype == dns.TypeA:
			rr := &dns.A{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}}
			copy(rr.A[:], ip.AsSlice())
			reply.Answer = append(reply.Answer, rr)
		case ip.Is6() && question.Qtype == dns.TypeAAAA:
			rr := &dns.AAAA{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 30}}
			copy(rr.AAAA[:], ip.AsSlice())
			reply.Answer = append(reply.Answer, rr)
		}
	}
	return reply.Pack()
}

// Serve the Tailscale service DNS endpoint over in-memory TCP. Network DNS
// is never opened here; each request is evaluated against the current map.
func serveLiteDNS(conn net.Conn, client *lite.Client) {
	var header [2]byte
	for {
		if _, err := io.ReadFull(conn, header[:]); err != nil { return }
		size := int(binary.BigEndian.Uint16(header[:]))
		if size < 12 { return }
		req := make([]byte, size)
		if _, err := io.ReadFull(conn, req); err != nil { return }
		resp, err := liteDNSQuery(context.Background(), client, req)
		if err != nil || len(resp) > 65535 { return }
		binary.BigEndian.PutUint16(header[:], uint16(len(resp)))
		if _, err := conn.Write(header[:]); err != nil { return }
		if _, err := conn.Write(resp); err != nil { return }
	}
}

// These types are intentionally referenced through net/netip and the DNS
// callback to make ownership of MagicDNS parsing explicit.
var _ netip.Addr
