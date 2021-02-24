package shadowsocks

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/net/common"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

var (
	OBFS  = "obfs-local"
	V2RAY = "v2ray"
)

type shadowsocks struct {
	cipher     core.Cipher
	server     string
	port       string
	plugin     string
	pluginOpt  string
	pluginFunc func(conn net.Conn) net.Conn

	lookUp func(string) ([]net.IP, error)
	cache  []net.IP
	ip     bool
}

func NewShadowsocks(
	cipherName string,
	password string,
	server, port string,
	plugin, pluginOpt string,
) (*shadowsocks, error) {
	cipher, err := core.PickCipher(strings.ToUpper(cipherName), nil, password)
	if err != nil {
		return nil, err
	}
	s := &shadowsocks{
		cipher:    cipher,
		server:    server,
		port:      port,
		plugin:    strings.ToUpper(plugin),
		pluginOpt: pluginOpt,
		cache:     []net.IP{},
		ip:        net.ParseIP(server) != nil,
		lookUp: func(s string) ([]net.IP, error) {
			return common.LookupIP(net.DefaultResolver, s)
		},
	}
	switch strings.ToLower(plugin) {
	case OBFS:
		s.pluginFunc = func(conn net.Conn) net.Conn {
			conn, err := NewObfs(conn, pluginOpt)
			if err != nil {
				log.Println(err)
				return nil
			}
			return conn
		}
	case V2RAY:
		s.pluginFunc = func(conn net.Conn) net.Conn {
			conn, err := NewV2raySelf(conn, pluginOpt)
			if err != nil {
				log.Println(err)
				return nil
			}
			return conn
		}
	default:
		s.pluginFunc = func(conn net.Conn) net.Conn { return conn }
	}

	return s, nil
}

func (s *shadowsocks) Conn(host string) (conn net.Conn, err error) {
	conn, err = s.getTCPConn()
	if err != nil {
		return nil, fmt.Errorf("[ss] dial to %s -> %v", s.server, err)
	}
	_ = conn.(*net.TCPConn).SetKeepAlive(true)
	conn = s.cipher.StreamConn(s.pluginFunc(conn))
	if _, err = conn.Write(socks.ParseAddr(host)); err != nil {
		return nil, fmt.Errorf("conn.Write -> host: %s, error: %v", host, err)
	}
	return conn, nil
}

func (s *shadowsocks) getTCPConn() (net.Conn, error) {
	if s.ip {
		return net.Dial("tcp", net.JoinHostPort(s.server, s.port))
	}
	conn, err := s.tcpDial()
	if err == nil {
		return conn, err
	}
	s.cache, _ = s.lookUp(s.server)
	return s.tcpDial()
}

func (s *shadowsocks) tcpDial() (net.Conn, error) {
	for index := range s.cache {
		conn, err := net.Dial("tcp", net.JoinHostPort(s.cache[index].String(), s.port))
		if err != nil {
			continue
		}
		return conn, nil
	}
	return nil, errors.New("shadowsocks dial failed")
}

func (s *shadowsocks) udpHandle(listener *net.UDPConn, remoteAddr net.Addr, b []byte) error {
	host, port, err := net.SplitHostPort(s.server)
	if err != nil {
		return err
	}
	ip, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return err
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip.String(), port))
	if err != nil {
		return err
	}

	pc, err := net.ListenPacket("udp", "")
	if err != nil {
		return err
	}
	pc = s.cipher.PacketConn(pc)
	_, err = pc.WriteTo(b[3:], addr)
	if err != nil {
		return err
	}

	respBuff := common.BuffPool.Get().([]byte)
	defer common.BuffPool.Put(respBuff[:cap(respBuff)])
	n, _, err := pc.ReadFrom(respBuff)
	if err != nil {
		return err
	}

	_, err = listener.WriteTo(append([]byte{0, 0, 0}, respBuff[:n]...), remoteAddr)
	return err
}

func (s *shadowsocks) UDPConn(listener *net.UDPConn, target net.Addr, b []byte) (err error) {
	host, port, err := net.SplitHostPort(s.server)
	if err != nil {
		return err
	}
	ip, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return err
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip.String(), port))
	if err != nil {
		return err
	}

	pc, err := net.ListenPacket("udp", "")
	if err != nil {
		return err
	}
	pc = s.cipher.PacketConn(pc)

	_, err = pc.WriteTo(b[3:], addr)
	if err != nil {
		return err
	}

	buf := common.BuffPool.Get().([]byte)
	defer common.BuffPool.Put(buf)
	go func() {
		for {
			_ = pc.SetReadDeadline(time.Now().Add(time.Second * 5))
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				log.Println(err)
				break
			}
			_, err = listener.WriteTo(append([]byte{0, 0, 0}, buf[:n]...), target)
			if err != nil {
				log.Println(err)
				break
			}
		}
	}()
	return
}

func (s *shadowsocks) SetResolver(l func(string) ([]net.IP, error)) {
	if l == nil {
		return
	}
	s.lookUp = l
}
