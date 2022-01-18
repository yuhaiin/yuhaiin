package shadowsocksr

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"

	socks5client "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	shadowsocksr "github.com/v2rayA/shadowsocksR"
	"github.com/v2rayA/shadowsocksR/obfs"
	Protocol "github.com/v2rayA/shadowsocksR/protocol"
	"github.com/v2rayA/shadowsocksR/ssr"
	"github.com/v2rayA/shadowsocksR/streamCipher"
)

var _ proxy.Proxy = (*Shadowsocksr)(nil)

type Shadowsocksr struct {
	encryptMethod   string
	encryptPassword string
	obfs            string
	obfsParam       string
	obfsData        interface{}
	protocol        string
	protocolParam   string
	protocolData    interface{}

	p proxy.Proxy
}

func NewShadowsocksr(host, port, method, password, obfs, obfsParam, protocol, protocolParam string) func(proxy.Proxy) (proxy.Proxy, error) {
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		s := &Shadowsocksr{
			encryptMethod:   method,
			encryptPassword: password,
			obfs:            obfs,
			obfsParam:       obfsParam,
			protocol:        protocol,
			protocolParam:   protocolParam,

			p: p,
		}
		s.protocolData = new(Protocol.AuthData)
		return s, nil
	}
}

func (s *Shadowsocksr) Conn(addr string) (net.Conn, error) {
	c, err := s.p.Conn(addr)
	if err != nil {
		return nil, fmt.Errorf("get conn failed: %w", err)
	}

	cipher, err := streamCipher.NewStreamCipher(s.encryptMethod, s.encryptPassword)
	if err != nil {
		return nil, err
	}
	ssrconn := shadowsocksr.NewSSTCPConn(c, cipher)
	if ssrconn.Conn == nil || ssrconn.RemoteAddr() == nil {
		return nil, errors.New("[ssr] nil connection")
	}

	// should initialize obfs/protocol now
	rs := strings.Split(ssrconn.RemoteAddr().String(), ":")
	port, _ := strconv.ParseUint(rs[1], 10, 16)

	ssrconn.IObfs = obfs.NewObfs(s.obfs)
	if ssrconn.IObfs == nil {
		return nil, errors.New("[ssr] unsupported obfs type: " + s.obfs)
	}

	obfsServerInfo := &ssr.ServerInfo{
		Host:   rs[0],
		Port:   uint16(port),
		TcpMss: 1460,
		Param:  s.obfsParam,
	}
	ssrconn.IObfs.SetServerInfo(obfsServerInfo)

	ssrconn.IProtocol = Protocol.NewProtocol(s.protocol)
	if ssrconn.IProtocol == nil {
		return nil, errors.New("[ssr] unsupported protocol type: " + s.protocol)
	}

	protocolServerInfo := &ssr.ServerInfo{
		Host:   rs[0],
		Port:   uint16(port),
		TcpMss: 1460,
		Param:  s.protocolParam,
	}
	ssrconn.IProtocol.SetServerInfo(protocolServerInfo)

	if s.obfsData == nil {
		s.obfsData = ssrconn.IObfs.GetData()
	}
	ssrconn.IObfs.SetData(s.obfsData)

	if s.protocolData == nil {
		s.protocolData = ssrconn.IProtocol.GetData()
	}
	ssrconn.IProtocol.SetData(s.protocolData)

	target, err := socks5client.ParseAddr(addr)
	if err != nil {
		return nil, err
	}
	if _, err := ssrconn.Write(target); err != nil {
		_ = ssrconn.Close()
		return nil, err
	}
	return ssrconn, nil
}

func (s *Shadowsocksr) PacketConn(addr string) (net.PacketConn, error) {
	return net.ListenPacket("udp", "")
}
