package register

import (
	"crypto/rand"
	"errors"
	mrand "math/rand/v2"
	"net"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"google.golang.org/protobuf/proto"
)

func ConvertTransport(x *listener.Transport) (*protocol.Protocol, error) {
	var pro *protocol.Protocol
	switch x.WhichTransport() {
	case listener.Transport_TlsAuto_case:
		pro = protocol.Protocol_builder{
			Tls: protocol.TlsConfig_builder{
				Enable:      proto.Bool(true),
				NextProtos:  x.GetTlsAuto().GetNextProtos(),
				ServerNames: replacePatternServernames(x.GetTlsAuto().GetServernames()),
				CaCert:      [][]byte{x.GetTlsAuto().GetCaCert()},
				EchConfig:   x.GetTlsAuto().GetEch().GetConfig(),
			}.Build(),
		}.Build()
	case listener.Transport_Reality_case:
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

		pro = protocol.Protocol_builder{
			Reality: protocol.Reality_builder{
				ServerName: &servername,
				ShortId:    &shortid,
				PublicKey:  proto.String(x.GetReality().GetPublicKey()),
			}.Build(),
		}.Build()

	case listener.Transport_Http2_case:
		pro = protocol.Protocol_builder{
			Http2: protocol.Http2_builder{
				Concurrency: proto.Int32(10),
			}.Build(),
		}.Build()

	case listener.Transport_Mux_case:
		pro = protocol.Protocol_builder{
			Mux: protocol.Mux_builder{
				Concurrency: proto.Int32(10),
			}.Build(),
		}.Build()

	case listener.Transport_Websocket_case:
		pro = protocol.Protocol_builder{
			Websocket: protocol.Websocket_builder{
				Host: proto.String(rand.Text()),
				Path: proto.String(rand.Text()),
			}.Build(),
		}.Build()

	case listener.Transport_Normal_case:
		pro = protocol.Protocol_builder{
			None: &protocol.None{},
		}.Build()
	case listener.Transport_Tls_case, listener.Transport_Grpc_case:
		// because we can't get the ca cert, so please use tls auto instead
		fallthrough
	default:
		return nil, errors.New("unsupport transport")
	}

	return pro, nil
}

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

func ConvertProtocol(x *listener.Inbound) (*protocol.Protocol, error) {
	var pro *protocol.Protocol
	switch x.WhichProtocol() {
	case listener.Inbound_Http_case:
		pro = protocol.Protocol_builder{
			Http: protocol.Http_builder{
				User:     proto.String(x.GetHttp().GetUsername()),
				Password: proto.String(x.GetHttp().GetPassword()),
			}.Build(),
		}.Build()
	case listener.Inbound_Socks5_case:
		pro = protocol.Protocol_builder{
			Socks5: protocol.Socks5_builder{
				User:     proto.String(x.GetSocks5().GetUsername()),
				Password: proto.String(x.GetSocks5().GetPassword()),
			}.Build(),
		}.Build()
	case listener.Inbound_Mix_case:
		pro = protocol.Protocol_builder{
			Socks5: protocol.Socks5_builder{
				User:     proto.String(x.GetMix().GetUsername()),
				Password: proto.String(x.GetMix().GetPassword()),
			}.Build(),
		}.Build()

	case listener.Inbound_None_case:
		pro = protocol.Protocol_builder{
			None: &protocol.None{},
		}.Build()

	case listener.Inbound_Yuubinsya_case:
		pro = protocol.Protocol_builder{
			Yuubinsya: protocol.Yuubinsya_builder{
				Password:      proto.String(x.GetYuubinsya().GetPassword()),
				TcpEncrypt:    proto.Bool(x.GetYuubinsya().GetTcpEncrypt()),
				UdpEncrypt:    proto.Bool(x.GetYuubinsya().GetUdpEncrypt()),
				UdpOverStream: proto.Bool(!x.GetYuubinsya().GetUdpEncrypt() && x.GetYuubinsya().GetTcpEncrypt()),
			}.Build(),
		}.Build()

	case listener.Inbound_Socks4A_case:
		// don't support socks4a client
		fallthrough
	case listener.Inbound_Tun_case,
		listener.Inbound_Redir_case,
		listener.Inbound_Tproxy_case,
		listener.Inbound_ReverseHttp_case,
		listener.Inbound_ReverseTcp_case:
		fallthrough
	default:
		return nil, errors.New("unsupport protocol")
	}

	return pro, nil
}

func ConvertNetwork(x *listener.Inbound) (*protocol.Protocol, error) {
	var pro *protocol.Protocol
	switch x.WhichNetwork() {
	case listener.Inbound_Tcpudp_case:
		host, portstr, err := net.SplitHostPort(x.GetTcpudp().GetHost())
		if err != nil {
			return nil, err
		}

		port, err := strconv.ParseUint(portstr, 10, 16)
		if err != nil {
			return nil, err
		}

		pro = protocol.Protocol_builder{
			Simple: protocol.Simple_builder{
				Host: proto.String(host),
				Port: proto.Int32(int32(port)),
			}.Build(),
		}.Build()
	case listener.Inbound_Quic_case:
		pro = protocol.Protocol_builder{
			Quic: protocol.Quic_builder{
				Host: proto.String(x.GetQuic().GetHost()),
				// same as tls, we can't get the ca cert so
				// TODO tls auto for quic
				Tls: &protocol.TlsConfig{},
			}.Build(),
		}.Build()
	case listener.Inbound_Empty_case, listener.Inbound_Network_not_set_case:
		pro = protocol.Protocol_builder{
			None: &protocol.None{},
		}.Build()

	default:
		return nil, errors.New("unsupport network")
	}

	return pro, nil
}
