package vmess

import (
	"fmt"
	"net"
	"strconv"
	"time"

	gitsrcVmess "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vmess/gitsrcvmess"
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
	client *gitsrcVmess.Client
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
) (*Vmess, error) {
	if fakeType != "none" {
		return nil, fmt.Errorf("not support [fake type: %s] now", fakeType)
	}

	client, err := gitsrcVmess.NewClient(uuid, security, int(alterID))
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
	conn, err = v.GetConn()
	if err != nil {
		return nil, fmt.Errorf("get conn failed: %v", err)
	}

	if x, ok := conn.(*net.TCPConn); ok {
		x.SetKeepAlive(true)
	}

	switch v.net {
	case "ws":
		// conn, err = v.webSocket(conn)
		conn, err = WebsocketDial(conn, v.host, v.path, v.cert, v.tls)
	case "quic":
		// conn, err = v.quic(conn)
		conn, err = QuicDial("udp", v.address, int(v.port), v.host, v.cert)
	}
	if err != nil {
		return nil, fmt.Errorf("net create failed: %v", err)
	}

	return v.client.NewConn(conn, "tcp", host)
}

//UDPConn packet transport connection
func (v *Vmess) UDPConn(host string) (conn net.PacketConn, err error) {
	c, err := v.GetConn()
	if err != nil {
		return nil, fmt.Errorf("get conn failed: %v", err)
	}

	if x, ok := c.(*net.TCPConn); ok {
		_ = x.SetKeepAlive(true)
	}

	switch v.net {
	case "ws":
		c, err = WebsocketDial(c, v.host, v.path, v.cert, v.tls)
	case "quic":
		c, err = QuicDial("udp", v.address, int(v.port), v.host, v.cert)
	}
	if err != nil {
		return nil, fmt.Errorf("net create failed: %v", err)
	}
	c, err = v.client.NewConn(c, "udp", host)
	if err != nil {
		return nil, fmt.Errorf("vmess new conn failed: %v", err)
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(v.address, strconv.Itoa(int(v.port))))
	if err != nil {
		return nil, fmt.Errorf("resolve udp failed: %v", err)
	}
	return &vmessPacketConn{
		conn: c,
		addr: addr,
	}, nil
}

type vmessPacketConn struct {
	conn net.Conn
	addr net.Addr
}

func (v *vmessPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	i, err := v.conn.Read(b)
	return i, v.addr, err
}

func (v *vmessPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return v.conn.Write(b)
}

func (v *vmessPacketConn) Close() error {
	return v.conn.Close()
}

func (v *vmessPacketConn) LocalAddr() net.Addr {
	return v.conn.LocalAddr()
}

func (v *vmessPacketConn) SetDeadline(t time.Time) error {
	return v.conn.SetDeadline(t)
}

func (v *vmessPacketConn) SetReadDeadline(t time.Time) error {
	return v.conn.SetReadDeadline(t)
}
func (v *vmessPacketConn) SetWriteDeadline(t time.Time) error {
	return v.conn.SetWriteDeadline(t)
}
