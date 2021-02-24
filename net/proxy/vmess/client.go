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
	net      string
	netConfig

	client *gitsrcVmess.Client
}

type netConfig struct {
	tls     bool
	path    string
	host    string
	cert    string
	certRaw string
}

//NewVmess create new Vmess Client
func NewVmess(address string, port uint32, uuid string, securityType string, alterID uint32,
	net, netPath, netHost string, tls bool, cert, certRaw string) (*Vmess, error) {
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
		client:   client,
		net:      net,
		netConfig: netConfig{
			tls: tls,
		},
	}

	switch v.net {
	case "ws":
		v.path = netPath
		v.host = netHost
	case "quic":
		v.tls = true
		v.host = netHost
	}

	if v.tls {
		v.cert = cert
		v.certRaw = certRaw
	}
	fmt.Println(v)
	return v, nil
}

//Conn create a connection for host
func (v *Vmess) Conn(host string) (conn net.Conn, err error) {
	conn, err = v.getConn()
	if err != nil {
		return nil, fmt.Errorf("get conn failed: %v", err)
	}

	switch v.net {
	case "ws":
		conn, err = v.webSocket(conn)
	case "quic":
		conn, err = v.quic(conn)
	}
	if err != nil {
		return nil, fmt.Errorf("net create failed: %v", err)
	}

	return v.client.NewConn(conn, host)
}

func (v *Vmess) getConn() (net.Conn, error) {
	return net.DialTimeout("tcp", net.JoinHostPort(v.address, strconv.FormatUint(uint64(v.port), 10)), time.Second*10)
}

func (v *Vmess) webSocket(conn net.Conn) (net.Conn, error) {
	webConfig := &v2Websocket.Config{
		Path: v.path,
		Header: []*v2Websocket.Header{
			{
				Key:   "Host",
				Value: v.host,
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

	if v.tls {
		err := v.tlsConfig(streamConfig)
		if err != nil {
			return nil, fmt.Errorf("tls config failed: %v", err)
		}
	}

	streamSetting, err := internet.ToMemoryStreamConfig(streamConfig)
	if err != nil {
		return nil, err
	}
	return v2Websocket.Dial(context.Background(), v2rayNet.DestinationFromAddr(conn.RemoteAddr()), streamSetting)
}

func (v *Vmess) quic(conn net.Conn) (net.Conn, error) {
	transportSettings := &v2Quic.Config{
		Security: &protocol.SecurityConfig{Type: protocol.SecurityType_NONE},
	}

	streamConfig := &internet.StreamConfig{
		ProtocolName: "quic",
		TransportSettings: []*internet.TransportConfig{{
			ProtocolName: "quic",
			Settings:     serial.ToTypedMessage(transportSettings),
		}},
		SocketSettings: &internet.SocketConfig{
			Tfo: internet.SocketConfig_Enable,
		},
	}

	//quic 必须开启tls
	err := v.tlsConfig(streamConfig)
	if err != nil {
		return nil, fmt.Errorf("tls config failed: %v", err)
	}

	streamSetting, err := internet.ToMemoryStreamConfig(streamConfig)
	if err != nil {
		return nil, err
	}
	return v2Quic.Dial(context.Background(), v2rayNet.DestinationFromAddr(conn.RemoteAddr()), streamSetting)
}

func (v *Vmess) tlsConfig(streamConfig *internet.StreamConfig) error {
	tlsConfig := tls.Config{ServerName: v.host}
	if v.cert != "" || v.certRaw != "" {
		certificate := tls.Certificate{Usage: tls.Certificate_AUTHORITY_VERIFY}
		var err error
		certificate.Certificate, err = readCertificate(v.cert, v.certRaw)
		if err != nil {
			return errors.New("failed to read cert")
		}
		tlsConfig.Certificate = []*tls.Certificate{&certificate}
	}
	streamConfig.SecurityType = serial.GetMessageType(&tlsConfig)
	streamConfig.SecuritySettings = []*serial.TypedMessage{serial.ToTypedMessage(&tlsConfig)}
	return nil
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
