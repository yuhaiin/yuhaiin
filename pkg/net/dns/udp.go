package dns

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

func init() {
	Register(config.Dns_udp, NewDoU)
	Register(config.Dns_reserve, NewDoU)
}

var _ dns.DNS = (*udp)(nil)

type udp struct{ *client }

func NewDoU(config Config) dns.DNS {
	host := config.Host
	_, _, err := net.SplitHostPort(host)
	if e, ok := err.(*net.AddrError); ok {
		if strings.Contains(e.Err, "missing port in address") {
			host = net.JoinHostPort(host, "53")
		}
	}

	add, err := proxy.ParseAddress("udp", host)
	if err != nil {
		log.Println(err)
		add = proxy.EmptyAddr
	}

	return &udp{
		NewClient(config, func(req []byte) ([]byte, error) {
			var b = utils.GetBytes(utils.DefaultSize)
			defer utils.PutBytes(b)

			conn, err := config.Dialer.PacketConn(add)
			if err != nil {
				return nil, fmt.Errorf("get packetConn failed: %v", err)
			}
			defer conn.Close()

			err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if err != nil {
				return nil, fmt.Errorf("set read deadline failed: %v", err)
			}

			_, err = conn.WriteTo(req, add)
			if err != nil {
				return nil, err
			}

			err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if err != nil {
				return nil, fmt.Errorf("set read deadline failed: %v", err)
			}

			nn, _, err := conn.ReadFrom(b)
			return b[:nn], err
		})}
}

func (n *udp) Close() error { return nil }
