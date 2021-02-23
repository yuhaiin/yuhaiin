package vmess

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	gitsrcVmess "github.com/Asutorufa/yuhaiin/net/proxy/vmess/gitsrcvmess"
	v2rayNet "v2ray.com/core/common/net"
	"v2ray.com/core/common/platform/filesystem"
	"v2ray.com/core/common/protocol"
	"v2ray.com/core/common/serial"
	"v2ray.com/core/transport/internet"
	v2Quic "v2ray.com/core/transport/internet/quic"
	"v2ray.com/core/transport/internet/tls"
	v2Websocket "v2ray.com/core/transport/internet/websocket"
)

//Vmess vmess client
type Vmess struct {
	address  string
	port     uint32
	uuid     string
	security string
	alterID  uint32
	websocket

	client *gitsrcVmess.Client
}

type websocket struct {
	path string
	host string
}

//NewVmess create new Vmess Client
func NewVmess(address string, port uint32, uuid string, securityType string, alterID uint32, net string,
	netPath, netHost string) (*Vmess, error) {
	client, err := gitsrcVmess.NewClient(uuid, securityType, int(alterID))
	if err != nil {
		return nil, fmt.Errorf("new vmess client failed: %v", err)
	}
	v := &Vmess{
		address:  address,
		port:     port,
		uuid:     uuid,
		security: securityType,
		alterID:  alterID,
		websocket: websocket{
			path: netPath,
			host: netHost,
		},
		client: client,
	}

	switch net {
	case "ws":
		v.websocket = websocket{
			path: netPath,
			host: netHost,
		}
	}
	return v, nil
}

//Conn create a connection for host
func (v *Vmess) Conn(host string) (conn net.Conn, err error) {
	conn, err = v.getConn()
	if err != nil {
		return nil, fmt.Errorf("get conn failed: %v", err)
	}
	conn, err = webSocket(conn, v.path, v.host)
	if err != nil {
		return nil, fmt.Errorf("websocket create failed: %v", err)
	}
	return v.client.NewConn(conn, host)
}

func (v *Vmess) getConn() (net.Conn, error) {
	return net.DialTimeout("tcp", net.JoinHostPort(v.address, strconv.FormatUint(uint64(v.port), 10)), time.Second*10)
}

func webSocket(conn net.Conn, path, host string) (net.Conn, error) {
	webConfig := &v2Websocket.Config{
		Path: path,
		Header: []*v2Websocket.Header{
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
	return v2Websocket.Dial(context.Background(), v2rayNet.DestinationFromAddr(conn.RemoteAddr()), streamSetting)
}

func quic(conn net.Conn, path, host, cert, certRaw string) (net.Conn, error) {
	transportSettings := &v2Quic.Config{
		Security: &protocol.SecurityConfig{Type: protocol.SecurityType_NONE},
	}

	streamConfig := &internet.StreamConfig{
		ProtocolName: "websocket",
		TransportSettings: []*internet.TransportConfig{{
			ProtocolName: "websocket",
			Settings:     serial.ToTypedMessage(transportSettings),
		}},
		SocketSettings: &internet.SocketConfig{
			Tfo: internet.SocketConfig_Enable,
		},
	}

	//quic 必须开启tls
	tlsConfig := tls.Config{ServerName: host}
	if cert != "" || certRaw != "" {
		certificate := tls.Certificate{Usage: tls.Certificate_AUTHORITY_VERIFY}
		var err error
		certificate.Certificate, err = readCertificate(cert, certRaw)
		if err != nil {
			return nil, errors.New("failed to read cert")
		}
		tlsConfig.Certificate = []*tls.Certificate{&certificate}
	}
	streamConfig.SecurityType = serial.GetMessageType(&tlsConfig)
	streamConfig.SecuritySettings = []*serial.TypedMessage{serial.ToTypedMessage(&tlsConfig)}

	streamSetting, err := internet.ToMemoryStreamConfig(streamConfig)
	if err != nil {
		return nil, err
	}
	return v2Quic.Dial(context.Background(), v2rayNet.DestinationFromAddr(conn.RemoteAddr()), streamSetting)
}

func readCertificate(cert, certRaw string) ([]byte, error) {
	if cert != "" {
		return filesystem.ReadFile(cert)
	}
	if certRaw != "" {
		certHead := "-----BEGIN CERTIFICATE-----"
		certTail := "-----END CERTIFICATE-----"
		fixedCert := certHead + "\n" + certRaw + "\n" + certTail
		return []byte(fixedCert), nil
	}
	return nil, fmt.Errorf("can't get cert or certRaw")
}
