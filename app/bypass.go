package app

import (
	"errors"
	"fmt"
	"net"
	"time"
)

//BypassManager .
type BypassManager struct {
	bypass   bool
	nodeHash string

	lookup func(string) ([]net.IP, error)
	mapper func(string) (mark int, isIP bool)

	Forward       func(string) (net.Conn, error)
	ForwardPacket func(string) (net.PacketConn, error)
	proxy         func(string) (net.Conn, error)
	proxyPacket   func(string) (net.PacketConn, error)

	dialer      net.Dialer
	connManager *connManager
}

//NewBypassManager .
func NewBypassManager(bypass bool, mapper func(s string) (int, bool),
	lookup func(string) ([]net.IP, error)) (*BypassManager, error) {
	if mapper == nil {
		return nil, fmt.Errorf("mapper is nil")
	}

	if lookup == nil {
		lookup = net.LookupIP
	}

	m := &BypassManager{
		dialer: net.Dialer{
			Timeout: 15 * time.Second,
		},
		lookup: lookup,
		proxy: func(host string) (conn net.Conn, err error) {
			return net.DialTimeout("tcp", host, 15*time.Second)
		},
		proxyPacket: func(s string) (net.PacketConn, error) {
			return net.ListenPacket("udp", "")
		},
		mapper:      mapper,
		connManager: newConnManager(),
	}

	m.SetBypass(bypass)

	return m, nil
}

func (m *BypassManager) SetLookup(f func(string) ([]net.IP, error)) {
	if f != nil {
		m.lookup = f
	}
}

func (m *BypassManager) SetMapper(f func(string) (int, bool)) {
	if f != nil {
		m.mapper = f
	}
}

// https://myexternalip.com/raw
func (m *BypassManager) dial(network, host string) (conn interface{}, err error) {
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		return nil, fmt.Errorf("split host [%s] failed: %v", host, err)
	}

	mark, markType := m.mapper(hostname)

	if mark == others {
		fmt.Printf("[%s] -> %s, mode: default(proxy)\n", host, network)
	} else {
		fmt.Printf("[%s] -> %s, mode: %s\n", host, network, modeMapping[mark])
	}

	switch markType {
	case true:
		conn, err = m.dialIP(network, host, mark)
	case false:
		conn, err = m.dialDomain(network, hostname, port, mark)
	}

	return conn, err
}

func (m *BypassManager) dialIP(network, host string, des interface{}) (conn interface{}, err error) {
	if des == block {
		return nil, errors.New("block IP: " + host)
	}
	if des == direct {
		goto _direct
	}

	if network == "udp" {
		return m.proxyPacket(host)
	}
	return m.proxy(host)
_direct:
	if network == "udp" {
		conn, err = net.ListenPacket("udp", "")
	} else {
		conn, err = m.dialer.Dial("tcp", host)
	}
	if err != nil {
		return nil, fmt.Errorf("match direct -> %v", err)
	}
	return conn, err
}

func (m *BypassManager) dialDomain(network, hostname, port string, des interface{}) (conn interface{}, err error) {
	if des == block {
		return nil, errors.New("block domain: " + hostname)
	}
	if des == direct {
		goto _direct
	}

	if network == "udp" {
		return m.proxyPacket(net.JoinHostPort(hostname, port))
	}
	return m.proxy(net.JoinHostPort(hostname, port))
_direct:
	switch network {
	case "udp":
		conn, err = net.ListenPacket("udp", "")
	default:
		ip, err := m.lookup(hostname)
		if err != nil {
			return nil, fmt.Errorf("dns resolve failed: %v", err)
		}
		for i := range ip {
			conn, err = m.dialer.Dial("tcp", net.JoinHostPort(ip[i].String(), port))
			if err != nil {
				continue
			}
			return conn, err
		}
	}
	if conn == nil || err != nil {
		return nil, fmt.Errorf("get direct conn failed: %v", err)
	}
	return
}

//SetProxy .
func (m *BypassManager) SetProxy(
	conn func(string) (net.Conn, error),
	packetConn func(string) (net.PacketConn, error),
	hash string,
) {
	if m.nodeHash == hash {
		return
	}
	if conn == nil {
		m.proxy = func(host string) (conn net.Conn, err error) {
			return net.DialTimeout("tcp", host, 15*time.Second)
		}
	} else {
		m.proxy = conn
	}

	if packetConn == nil {
		m.proxyPacket = func(s string) (net.PacketConn, error) {
			return net.ListenPacket("udp", "")
		}
	} else {
		m.proxyPacket = packetConn
	}

	m.nodeHash = hash
}

func (m *BypassManager) setForward(network string) {
	if network == "udp" {
		m.ForwardPacket = func(s string) (net.PacketConn, error) {
			conn, err := m.dial("udp", s)
			if err != nil {
				return nil, err
			}
			if x, ok := conn.(net.PacketConn); ok {
				return x, nil
			}
			return nil, fmt.Errorf("conn is not net.PacketConn")
		}
		return
	}
	m.Forward = func(s string) (net.Conn, error) {
		conn, err := m.dial("tcp", s)
		if err != nil {
			return nil, err
		}
		if x, ok := conn.(net.Conn); ok {
			return m.connManager.newConn(s, x), nil
		}
		return nil, fmt.Errorf("conn is not net.Conn")
	}
}

func (m *BypassManager) SetBypass(b bool) {
	if m.bypass == b {
		if m.Forward == nil {
			m.setForward("tcp")
		}
		if m.ForwardPacket == nil {
			m.setForward("udp")
		}
		return
	}

	m.bypass = b
	switch b {
	case false:
		m.Forward = m.proxy
		m.ForwardPacket = m.proxyPacket
	default:
		m.setForward("tcp")
		m.setForward("udp")
	}
}

func (m *BypassManager) GetDownload() uint64 {
	return m.connManager.GetDownload()
}

func (m *BypassManager) GetUpload() uint64 {
	return m.connManager.GetUpload()
}
