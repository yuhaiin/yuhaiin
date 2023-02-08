package main

import (
	"crypto/tls"
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
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
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
	listener.Yuubinsya
}

func (c *Config) ServerConfig(dialer proxy.Proxy) (yuubinsya.Config, error) {
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

func unmarshalProtoJson(file string, c proto.Message) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	return protojson.Unmarshal(data, c)
}

func main() {
	protocol := flag.String("c", "", "-c, protocol config")
	socks5 := flag.String("s5", "", "-s5, socks5 config(host and bypass)")
	flag.Parse()

	config := &Config{Yuubinsya: listener.Yuubinsya{}}

	if err := unmarshalProtoJson(*protocol, &config.Yuubinsya); err != nil {
		log.Fatal(err)
	}

	var socks5Config Socks5Config
	if *socks5 != "" {
		if err := unmarshalJson(*socks5, &socks5Config); err != nil {
			log.Fatal(err)
		}
	}

	dialer, err := socks5Config.Dialer()
	if err != nil {
		log.Fatal(err)
	}

	sc, err := config.ServerConfig(dialer)
	if err != nil {
		log.Fatal(err)
	}

	y, err := yuubinsya.NewServer(sc)
	if err != nil {
		log.Fatal(err)
	}

	if err = y.Start(); err != nil {
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
