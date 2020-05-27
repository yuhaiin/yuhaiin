package client

import (
	"context"
	"errors"
	"flag"
	"strings"

	"github.com/golang/protobuf/proto"
	"v2ray.com/core/common/net"
	"v2ray.com/core/common/platform/filesystem"
	"v2ray.com/core/common/protocol"
	"v2ray.com/core/common/serial"
	"v2ray.com/core/transport/internet"
	"v2ray.com/core/transport/internet/quic"
	"v2ray.com/core/transport/internet/tls"
	"v2ray.com/core/transport/internet/websocket"
)

// some from https://github.com/shadowsocks/v2ray-plugin/blob/master/main.go
func NewV2ray(conn net.Conn, options string) (net.Conn, error) {
	var (
		fastOpen   = flag.Bool("fast-open", false, "Enable TCP fast open.")
		path       = flag.String("path", "/", "URL path for websocket.")
		host       = flag.String("host", "cloudfront.com", "Hostname for server.")
		tlsEnabled = flag.Bool("tls", false, "Enable TLS.")
		cert       = flag.String("cert", "", "Path to TLS certificate file. Overrides certRaw. Default: ~/.acme.sh/{host}/fullchain.cer")
		certRaw    = flag.String("certRaw", "", "Raw TLS certificate content. Intended only for Android.")
		mode       = flag.String("mode", "websocket", "Transport mode: websocket, quic (enforced tls).")
		//mux        = flag.Int("mux", 1, "Concurrent multiplexed connections (websocket client mode only).")
	)
	readCertificate := func() ([]byte, error) {
		if *cert != "" {
			return filesystem.ReadFile(*cert)
		}
		if *certRaw != "" {
			certHead := "-----BEGIN CERTIFICATE-----"
			certTail := "-----END CERTIFICATE-----"
			fixedCert := certHead + "\n" + *certRaw + "\n" + certTail
			return []byte(fixedCert), nil
		}
		panic("thou shalt not reach hear")
	}
	for _, x := range strings.Split(options, ";") {
		if strings.Contains(x, "=") {
			s := strings.Split(x, "=")
			switch s[0] {
			case "mode":
				*mode = s[1]
			case "path":
				*path = s[1]
			case "cert":
				*cert = s[1]
			case "certRaw":
				*certRaw = s[1]
			case "fastOpen":
				*fastOpen = true
			}
		}
		if x == "tls" {
			*tlsEnabled = true
		}
	}

	var transportSettings proto.Message
	//var connectionReuse bool
	switch *mode {
	case "websocket":
		transportSettings = &websocket.Config{
			Path: *path,
			Header: []*websocket.Header{
				{Key: "Host", Value: *host},
			},
		}
		//if *mux != 0 {
		//	connectionReuse = true
		//}
	case "quic":
		transportSettings = &quic.Config{
			Security: &protocol.SecurityConfig{Type: protocol.SecurityType_NONE},
		}
		*tlsEnabled = true
	default:
		return nil, errors.New("unsupported mode:" + *mode)
	}
	streamConfig := internet.StreamConfig{
		ProtocolName: *mode,
		TransportSettings: []*internet.TransportConfig{{
			ProtocolName: *mode,
			Settings:     serial.ToTypedMessage(transportSettings),
		}},
	}

	if *fastOpen {
		streamConfig.SocketSettings = &internet.SocketConfig{Tfo: internet.SocketConfig_Enable}
	}

	if *tlsEnabled {
		tlsConfig := tls.Config{ServerName: *host}
		if *cert != "" || *certRaw != "" {
			certificate := tls.Certificate{Usage: tls.Certificate_AUTHORITY_VERIFY}
			var err error
			certificate.Certificate, err = readCertificate()
			if err != nil {
				return nil, errors.New("failed to read cert")
			}
			tlsConfig.Certificate = []*tls.Certificate{&certificate}
		}
		streamConfig.SecurityType = serial.GetMessageType(&tlsConfig)
		streamConfig.SecuritySettings = []*serial.TypedMessage{serial.ToTypedMessage(&tlsConfig)}
	}

	//senderConfig := proxyman.SenderConfig{StreamSettings: &streamConfig}
	//if connectionReuse {
	//	senderConfig.MultiplexSettings = &proxyman.MultiplexingConfig{Enabled: true, Concurrency: uint32(*mux)}
	//}

	streamSetting, err := internet.ToMemoryStreamConfig(&streamConfig)
	if err != nil {
		return nil, err
	}
	switch *mode {
	case "websocket":
		return websocket.Dial(context.Background(), net.DestinationFromAddr(conn.RemoteAddr()), streamSetting)
	case "quic":
		return quic.Dial(context.Background(), net.DestinationFromAddr(conn.RemoteAddr()), streamSetting)
	}
	return nil, err
}
