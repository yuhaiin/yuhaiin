package client

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	socks5client "github.com/Asutorufa/yuhaiin/net/proxy/socks5/client"
	shadowsocksr "github.com/mzz2017/shadowsocksR"
	"github.com/mzz2017/shadowsocksR/obfs"
	Protocol "github.com/mzz2017/shadowsocksR/protocol"
	"github.com/mzz2017/shadowsocksR/ssr"
	cipher2 "github.com/mzz2017/shadowsocksR/streamCipher"
)

type Shadowsocksr struct {
	addr string

	encryptMethod   string
	encryptPassword string
	obfs            string
	obfsParam       string
	obfsData        interface{}
	protocol        string
	protocolParam   string
	protocolData    interface{}
}

func NewShadowsocksrClient(addr, method, password, obfs, obfsParam, protocol, protocolParam string) (ssr *Shadowsocksr, err error) {
	s := &Shadowsocksr{
		addr:            addr,
		encryptMethod:   method,
		encryptPassword: password,
		obfs:            obfs,
		obfsParam:       obfsParam,
		protocol:        protocol,
		protocolParam:   protocolParam,
	}
	s.protocolData = new(Protocol.AuthData)
	return s, nil
}

func (s *Shadowsocksr) Conn(addr string) (net.Conn, error) {
	target, err := socks5client.ParseAddr(addr)
	if err != nil {
		return nil, err
	}
	c, err := net.Dial("tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("[ssr] dial to %s error: %s", s.addr, err)
	}

	cipher, err := cipher2.NewStreamCipher(s.encryptMethod, s.encryptPassword)
	if err != nil {
		return nil, err
	}
	ssrconn := shadowsocksr.NewSSTCPConn(c, cipher)
	if ssrconn.Conn == nil || ssrconn.RemoteAddr() == nil {
		return nil, errors.New("[ssr] nil connection")
	}

	// should initialize obfs/protocol now
	rs := strings.Split(ssrconn.RemoteAddr().String(), ":")
	port, _ := strconv.Atoi(rs[1])

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

	if _, err := ssrconn.Write(target); err != nil {
		_ = ssrconn.Close()
		return nil, err
	}
	return ssrconn, nil
}
