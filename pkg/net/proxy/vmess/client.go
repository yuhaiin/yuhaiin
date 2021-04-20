package vmess

import (
	"fmt"
	"net"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"

	gcvmess "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vmess/gitsrcvmess"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

//Vmess vmess client
type Vmess struct {
	address  string
	port     uint32
	uuid     string
	security string
	fakeType string
	alterID  uint32
	net      string
	netConfig

	*utils.ClientUtil
	client *gcvmess.Client
}

type netConfig struct {
	tls  bool
	path string
	host string
	cert string
}

//NewVmess create new Vmess Client
func NewVmess(
	address string, port uint32,
	uuid, security,
	fakeType string,
	alterID uint32,
	netType, netPath, netHost string,
	tls bool, cert string,
) (proxy.Proxy, error) {
	if fakeType != "none" {
		return nil, fmt.Errorf("not support [fake type: %s] now", fakeType)
	}

	client, err := gcvmess.NewClient(uuid, security, int(alterID))
	if err != nil {
		return nil, fmt.Errorf("new vmess client failed: %v", err)
	}

	v := &Vmess{
		address:    address,
		port:       port,
		uuid:       uuid,
		security:   security,
		fakeType:   fakeType,
		alterID:    alterID,
		client:     client,
		net:        netType,
		ClientUtil: utils.NewClientUtil(address, strconv.FormatUint(uint64(port), 10)),
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
	}
	// fmt.Println(v)
	return v, nil
}

//Conn create a connection for host
func (v *Vmess) Conn(host string) (conn net.Conn, err error) {
	return v.conn("tcp", host)
}

//PacketConn packet transport connection
func (v *Vmess) PacketConn(host string) (conn net.PacketConn, err error) {
	return v.conn("udp", host)
}

func (v *Vmess) conn(network, host string) (*gcvmess.Conn, error) {
	conn, err := v.GetConn()
	if err != nil {
		return nil, fmt.Errorf("get conn failed: %v", err)
	}

	if x, ok := conn.(*net.TCPConn); ok {
		_ = x.SetKeepAlive(true)
	}

	switch v.net {
	case "ws":
		conn, err = WebsocketDial(conn, v.host, v.path, v.cert, v.tls)
	case "quic":
		conn, err = QuicDial("udp", v.address, int(v.port), v.host, v.cert)
	}
	if err != nil {
		return nil, fmt.Errorf("net create failed: %v", err)
	}

	return v.client.NewConn(conn, network, host)
}
