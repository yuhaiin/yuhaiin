package vmess

import (
	"context"
	"fmt"
	"strings"

	"v2ray.com/core/common/net"
	"v2ray.com/core/common/protocol"
	"v2ray.com/core/common/serial"
	libVmess "v2ray.com/core/proxy/vmess"
	vmessOutbound "v2ray.com/core/proxy/vmess/outbound"
	"v2ray.com/core/transport"
	"v2ray.com/core/transport/internet"
	"v2ray.com/core/transport/internet/websocket"
)

type vmess struct {
	handler *vmessOutbound.Handler
}

func New(
	address string,
	port uint32,
	uuid string,
	securityType string,
	alterID uint32,
) *vmess {
	re := []*protocol.ServerEndpoint{
		{
			Address: net.NewIPOrDomain(net.ParseAddress(address)),
			Port:    port,
			User: []*protocol.User{
				{
					Account: serial.ToTypedMessage(
						&libVmess.Account{
							Id:      uuid,
							AlterId: alterID,
							SecuritySettings: &protocol.SecurityConfig{
								Type: protocol.SecurityType(protocol.SecurityType_value[strings.ToUpper(securityType)]),
							},
						},
					),
				},
			},
		},
	}
	h, err := vmessOutbound.New(context.Background(), &vmessOutbound.Config{
		Receiver: re,
	})
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return &vmess{
		handler: h,
	}
}

func (v *vmess) Conn() {
	v.handler.Process(context.Background(), &transport.Link{}, nil)
}

func webSocket(
	conn net.Conn,
	path,
	host string,
) (net.Conn, error) {
	webConfig := &websocket.Config{
		Path: path,
		Header: []*websocket.Header{
			{
				Key:   "Host",
				Value: host,
			},
		},
	}

	streamConfig := &internet.StreamConfig{
		ProtocolName: "websocket",
		TransportSettings: []*internet.TransportConfig{{
			ProtocolName: "websocket",
			Settings:     serial.ToTypedMessage(webConfig),
		}},
		SocketSettings: &internet.SocketConfig{
			Tfo: internet.SocketConfig_Enable,
		},
	}

	streamSetting, err := internet.ToMemoryStreamConfig(streamConfig)
	if err != nil {
		return nil, err
	}
	return websocket.Dial(context.Background(), net.DestinationFromAddr(conn.RemoteAddr()), streamSetting)
}
