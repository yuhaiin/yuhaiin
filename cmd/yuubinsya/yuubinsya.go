package main

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/mapper"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

type Socks5Config struct {
	Host    string   `json:"host"`
	Domains []string `json:"domains"`
}

func main() {
	host := flag.String("h", "", "-h, listen addr")
	password := flag.String("p", "", "-p, password")
	certFile := flag.String("c", "", "-c, server cert pem")
	keyFile := flag.String("k", "", "-k, server key pem")
	quic := flag.Bool("quic", false, "-quic")
	socks5 := flag.String("s5", "", "-s5, socks5 config(host and bypass)")
	flag.Parse()

	var err error
	var certPEM, keyPEM []byte

	if *certFile != "" && *keyFile != "" {
		certPEM, err = os.ReadFile(*certFile)
		if err != nil {
			log.Fatal(err)
		}
		keyPEM, err = os.ReadFile(*keyFile)
		if err != nil {
			log.Fatal(err)
		}
	}

	var dialer = &dialer{}
	if *socks5 != "" {
		z, err := os.ReadFile(*socks5)
		if err != nil {
			log.Fatal(err)
		}

		var config Socks5Config
		if err = json.Unmarshal(z, &config); err != nil {
			log.Fatal(err)
		}

		host, err := proxy.ParseAddress(0, config.Host)
		if err != nil {
			log.Fatal(err)
		}
		socks5, err := client.New(&protocol.Protocol_Socks5{
			Socks5: &protocol.Socks5{
				Hostname: config.Host,
			}})(yerror.Must(simple.New(&protocol.Protocol_Simple{
			Simple: &protocol.Simple{
				Host:             host.Hostname(),
				Port:             int32(host.Port().Port()),
				PacketConnDirect: true,
			},
		})(nil)))
		if err != nil {
			log.Fatal(err)
		}

		dialer.dialer = socks5
		dialer.mapper = mapper.NewMapper[struct{}]()

		for _, k := range config.Domains {
			dialer.mapper.Insert(k, struct{}{})
		}
	}

	y, err := yuubinsya.NewServer(dialer, *host, *password, certPEM, keyPEM, *quic)
	if err != nil {
		log.Fatal(err)
	}

	if *quic {
		err = y.StartQUIC()
	} else {
		err = y.Start()
	}

	if err != nil {
		log.Fatal(err)
	}
}

type dialer struct {
	dialer proxy.Proxy

	mapper *mapper.Combine[struct{}]
}

func (d *dialer) Conn(addr proxy.Address) (net.Conn, error) {
	if d.dialer != nil {
		if _, ok := d.mapper.Search(addr); ok {
			log.Printf("%v tcp forward to socks5", addr)
			return d.dialer.Conn(addr)
		}
	}
	return net.Dial("tcp", addr.String())
}

func (d *dialer) PacketConn(addr proxy.Address) (net.PacketConn, error) {
	if d.dialer != nil {
		if _, ok := d.mapper.Search(addr); ok {
			log.Printf("%v udp forward to socks5", addr)
			return d.dialer.PacketConn(addr)
		}
	}
	return direct.Default.PacketConn(addr)
}
