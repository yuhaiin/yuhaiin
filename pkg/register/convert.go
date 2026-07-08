package register

import (
	"crypto/rand"
	"errors"
	mrand "math/rand/v2"
	"net"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/schema/config"
	"github.com/Asutorufa/yuhaiin/pkg/schema/node"
)

func ConvertTransport(x *config.Transport) (*node.Protocol, error) {
	var pro *node.Protocol
	switch x.WhichTransport() {
	case config.Transport_TlsAuto_case:
		pro = node.Protocol_builder{
			Tls: node.TlsConfig_builder{
				Enable:      new(true),
				NextProtos:  x.GetTlsAuto().GetNextProtos(),
				ServerNames: replacePatternServernames(x.GetTlsAuto().GetServernames()),
				CaCert:      [][]byte{x.GetTlsAuto().GetCaCert()},
				EchConfig:   x.GetTlsAuto().GetEch().GetConfig(),
			}.Build(),
		}.Build()

	case config.Transport_Reality_case:
		var servername string
		if len(x.GetReality().GetServerName()) > 0 {
			servername = x.GetReality().GetServerName()[mrand.IntN(len(x.GetReality().GetServerName()))]
		} else {
			servername = rand.Text()
		}

		var shortid string
		if len(x.GetReality().GetShortId()) > 0 {
			shortid = x.GetReality().GetShortId()[mrand.IntN(len(x.GetReality().GetShortId()))]
		} else {
			shortid = rand.Text()
		}

		pro = node.Protocol_builder{
			Reality: node.Reality_builder{
				ServerName: &servername,
				ShortId:    &shortid,
				PublicKey:  new(x.GetReality().GetPublicKey()),
			}.Build(),
		}.Build()

	case config.Transport_Http2_case:
		pro = node.Protocol_builder{
			Http2: node.Http2_builder{
				Concurrency: ptr(int32(10)),
			}.Build(),
		}.Build()

	case config.Transport_Mux_case:
		pro = node.Protocol_builder{
			Mux: node.Mux_builder{
				Concurrency: ptr(int32(10)),
			}.Build(),
		}.Build()

	case config.Transport_Websocket_case:
		pro = node.Protocol_builder{
			Websocket: node.Websocket_builder{
				Host: new(rand.Text()),
				Path: new(rand.Text()),
			}.Build(),
		}.Build()

	case config.Transport_Normal_case:
		pro = node.Protocol_builder{
			None: &node.None{},
		}.Build()

	case config.Transport_Tls_case:
		// because we can't get the ca cert, so please use tls auto instead
		fallthrough

	default:
		return nil, errors.New("unsupport transport")
	}

	return pro, nil
}

func ptr[T any](v T) *T { return &v }

func replacePatternServernames(servernames []string) []string {
	var resp []string

	for _, v := range servernames {
		if len(v) == 0 {
			continue
		}

		if v[0] == '*' {
			resp = append(resp, rand.Text()+v[1:])
		} else {
			resp = append(resp, v)
		}
	}

	return resp
}

func ConvertProtocol(x *config.Inbound) (*node.Protocol, error) {
	var pro *node.Protocol
	switch x.WhichProtocol() {
	case config.Inbound_Http_case:
		pro = node.Protocol_builder{
			Http: node.Http_builder{
				User:     new(x.GetHttp().GetUsername()),
				Password: new(x.GetHttp().GetPassword()),
			}.Build(),
		}.Build()

	case config.Inbound_Socks5_case:
		pro = node.Protocol_builder{
			Socks5: node.Socks5_builder{
				User:     new(x.GetSocks5().GetUsername()),
				Password: new(x.GetSocks5().GetPassword()),
			}.Build(),
		}.Build()

	case config.Inbound_Mix_case:
		pro = node.Protocol_builder{
			Socks5: node.Socks5_builder{
				User:     new(x.GetMix().GetUsername()),
				Password: new(x.GetMix().GetPassword()),
			}.Build(),
		}.Build()

	case config.Inbound_None_case:
		pro = node.Protocol_builder{
			None: &node.None{},
		}.Build()

	case config.Inbound_Yuubinsya_case:
		pro = node.Protocol_builder{
			Yuubinsya: node.Yuubinsya_builder{
				Password:      new(x.GetYuubinsya().GetPassword()),
				UdpOverStream: new(true),
				UdpCoalesce:   new(x.GetYuubinsya().GetUdpCoalesce()),
			}.Build(),
		}.Build()

	case config.Inbound_Socks4A_case:
		// don't support socks4a client
		fallthrough

	case config.Inbound_Tun_case,
		config.Inbound_Redir_case,
		config.Inbound_Tproxy_case,
		config.Inbound_ReverseHttp_case,
		config.Inbound_ReverseTcp_case:
		fallthrough

	default:
		return nil, errors.New("unsupport protocol")
	}

	return pro, nil
}

func ConvertNetwork(x *config.Inbound) (*node.Protocol, error) {
	var pro *node.Protocol
	switch x.WhichNetwork() {
	case config.Inbound_Tcpudp_case:
		host, portstr, err := net.SplitHostPort(x.GetTcpudp().GetHost())
		if err != nil {
			return nil, err
		}

		port, err := strconv.ParseUint(portstr, 10, 16)
		if err != nil {
			return nil, err
		}

		pro = node.Protocol_builder{
			Simple: node.Simple_builder{
				Host: new(host),
				Port: new(int32(port)),
			}.Build(),
		}.Build()

	case config.Inbound_Quic_case:
		pro = node.Protocol_builder{
			Quic: node.Quic_builder{
				Host: new(x.GetQuic().GetHost()),
				// same as tls, we can't get the ca cert so
				// TODO tls auto for quic
				Tls: &node.TlsConfig{},
			}.Build(),
		}.Build()

	case config.Inbound_Empty_case, config.Inbound_Network_not_set_case:
		pro = node.Protocol_builder{
			None: &node.None{},
		}.Build()

	default:
		return nil, errors.New("unsupport network")
	}

	return pro, nil
}
