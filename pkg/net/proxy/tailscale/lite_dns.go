package tailscale

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	lite "github.com/yuhaiin/tailscale-lite"
)

// Fail closed on names outside the authorized MagicDNS table. The embedded
// endpoint never delegates a rejected query to the host's DNS resolver.
var errTailscaleDNSUnavailable = errors.New("tailscale: MagicDNS unavailable")

func liteDNSQuery(ctx context.Context, client *lite.Client, request []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errTailscaleDNSUnavailable
	}
	var query dns.Msg
	query.Data = request
	if err := query.Unpack(); err != nil {
		return nil, err
	}
	if len(query.Question) != 1 {
		reply := &dns.Msg{ID: query.ID, Response: true, Rcode: dns.RcodeFormatError}
		if err := reply.Pack(); err != nil { return nil, err }
		return reply.Data, nil
	}
	question := netapi.DNSQuestionFromRR(query.Question[0])
	reply := netapi.NewDNSMsg(question)
	reply.ID = query.ID
	reply.Opcode = query.Opcode
	reply.RecursionDesired = query.RecursionDesired
	reply.RecursionAvailable = false
	reply.Authoritative = true
	switch {
	case query.Opcode != dns.OpcodeQuery:
		reply.Rcode = dns.RcodeNotImplemented
	case question.Qclass != dns.ClassINET:
		reply.Rcode = dns.RcodeRefused
	default:
		ips, owned := client.LookupIP(question.Name)
		if !owned {
			reply.Rcode = dns.RcodeRefused
		} else if len(ips) == 0 {
			reply.Rcode = dns.RcodeNameError
		} else {
			for _, ip := range ips {
				hdr := dns.Header{Name: question.Name, Class: dns.ClassINET, TTL: 30}
				switch {
				case ip.Is4() && question.Qtype == dns.TypeA:
					reply.Answer = append(reply.Answer, &dns.A{Hdr: hdr, Addr: ip})
				case ip.Is6() && question.Qtype == dns.TypeAAAA:
					reply.Answer = append(reply.Answer, &dns.AAAA{Hdr: hdr, Addr: ip})
				}
			}
		}
	}
	if err := reply.Pack(); err != nil {
		return nil, err
	}
	return reply.Data, nil
}

// Serve the MagicDNS service endpoint over in-memory TCP. It does not create
// a host DNS socket. Requests are resolved against the current authorized map.
func serveLiteDNS(conn net.Conn, client *lite.Client) {
	var header [2]byte
	for {
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return
		}
		size := int(binary.BigEndian.Uint16(header[:]))
		if size < 12 {
			return
		}
		request := make([]byte, size)
		if _, err := io.ReadFull(conn, request); err != nil {
			return
		}
		reply, err := liteDNSQuery(context.Background(), client, request)
		if err != nil || len(reply) > 65535 {
			return
		}
		binary.BigEndian.PutUint16(header[:], uint16(len(reply)))
		if _, err := conn.Write(header[:]); err != nil {
			return
		}
		if _, err := conn.Write(reply); err != nil {
			return
		}
	}
}
