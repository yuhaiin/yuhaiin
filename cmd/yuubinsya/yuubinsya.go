package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/mapper"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
	"google.golang.org/protobuf/encoding/protojson"
)

type Socks5Config struct {
	Host    string   `json:"host"`
	Domains []string `json:"domains"`
}

func (s Socks5Config) Dialer() (*dialer, error) {
	var dialer = &dialer{}

	if s.Host == "" || len(s.Domains) > 0 {
		return dialer, nil
	}

	host, err := proxy.ParseAddress(0, s.Host)
	if err != nil {
		return nil, err
	}
	socks5, err := client.New(&protocol.Protocol_Socks5{
		Socks5: &protocol.Socks5{
			Hostname: s.Host,
		}})(yerror.Must(simple.New(&protocol.Protocol_Simple{
		Simple: &protocol.Simple{
			Host:             host.Hostname(),
			Port:             int32(host.Port().Port()),
			PacketConnDirect: true,
		},
	})(nil)))
	if err != nil {
		return nil, err
	}

	dialer.dialer = socks5
	dialer.mapper = mapper.NewMapper[struct{}]()

	for _, k := range s.Domains {
		dialer.mapper.Insert(k, struct{}{})
	}

	return dialer, nil
}

type Config struct {
	Inbounds []*Inbound   `json:"inbound"`
	Socks5   Socks5Config `json:"socks5"`
}

type Inbound struct{ listener.Yuubinsya }

func (c *Inbound) MarshalJSON() ([]byte, error) { return protojson.Marshal(&c.Yuubinsya) }
func (c *Inbound) UnmarshalJSON(b []byte) error { return protojson.Unmarshal(b, &c.Yuubinsya) }
func (c *Inbound) ServerConfig(dialer proxy.Proxy) (yuubinsya.Config, error) {
	var Type yuubinsya.Type
	var err error
	var tlsConfig *tls.Config
	switch p := c.Protocol.(type) {
	case *listener.Yuubinsya_Normal:
		Type = yuubinsya.TCP
	case *listener.Yuubinsya_Tls:
		Type = yuubinsya.TLS
		tlsConfig, err = listener.ParseTLS(p.Tls.GetTls())
	case *listener.Yuubinsya_Quic:
		Type = yuubinsya.QUIC
		tlsConfig, err = listener.ParseTLS(p.Quic.GetTls())
	case *listener.Yuubinsya_Websocket:
		Type = yuubinsya.WEBSOCKET
		tlsConfig, err = listener.ParseTLS(p.Websocket.GetTls())
	}
	if err != nil {
		return yuubinsya.Config{}, err
	}

	return yuubinsya.Config{
		Host:      c.Host,
		Password:  []byte(c.Password),
		TlsConfig: tlsConfig,
		Type:      Type,
		Dialer:    dialer,
	}, nil
}

func unmarshalJson(file string, c any) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, c)
}

func main() {
	configFile := flag.String("c", "", "-c, config")
	flag.Parse()

	config := &Config{}

	if err := unmarshalJson(*configFile, &config); err != nil {
		log.Fatal(err)
	}

	dialer, err := config.Socks5.Dialer()
	if err != nil {
		log.Fatal(err)
	}

	var wg sync.WaitGroup

	for _, p := range config.Inbounds {
		sc, err := p.ServerConfig(dialer)
		if err != nil {
			log.Fatal(err)
		}

		y, err := yuubinsya.NewServer(sc)
		if err != nil {
			log.Fatal(err)
		}
		wg.Add(1)

		go func() {
			defer wg.Done()
			if err = y.Start(); err != nil {
				log.Fatal(err)
			}
		}()
	}

	wg.Wait()
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
