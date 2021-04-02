package app

import (
	"fmt"
	"net"
	"time"
)

//BypassManager .
type BypassManager struct {
	bypass bool

	lookup func(string) ([]net.IP, error)
	mapper func(string) (mark int, isIP int)

	proxy       func(string) (net.Conn, error)
	proxyPacket func(string) (net.PacketConn, error)

	/*
	 * type\mark  others direct block
	 *	IP
	 * DOMAIN
	 */
	connMapper       [2][3]func(string) (net.Conn, error)
	packetConnMapper [3]func(string) (net.PacketConn, error)
	dialer           net.Dialer
	connManager      *connManager
}

//NewBypassManager .
func NewBypassManager(bypass bool, mapper func(s string) (int, int),
	lookup func(string) ([]net.IP, error)) (*BypassManager, error) {
	if mapper == nil {
		return nil, fmt.Errorf("mapper is nil")
	}

	if lookup == nil {
		lookup = net.LookupIP
	}

	m := &BypassManager{
		dialer: net.Dialer{Timeout: 11 * time.Second},
		lookup: lookup,
		proxy: func(host string) (conn net.Conn, err error) {
			return net.DialTimeout("tcp", host, 15*time.Second)
		},
		proxyPacket: func(s string) (net.PacketConn, error) {
			return net.ListenPacket("udp", "")
		},
		mapper:      mapper,
		connManager: newConnManager(),
		bypass:      bypass,
	}

	m.connMapper = [2][3]func(string) (net.Conn, error){
		/*
		 * type\mark  others block direct
		 *	IP
		 * DOMAIN
		 */
		{ // ip
			m.proxya,  // other
			blockConn, // block
			func(s string) (net.Conn, error) { // direct
				return m.dialer.Dial("tcp", s)
			},
		},
		{ // domain
			m.proxya,  // other
			blockConn, // block
			func(s string) (net.Conn, error) { // direct
				hostname, port, err := net.SplitHostPort(s)
				if err != nil {
					return nil, fmt.Errorf("split host [%s] failed: %v", s, err)
				}

				ip, err := m.lookup(hostname)
				if err != nil {
					return nil, fmt.Errorf("dns resolve failed: %v", err)
				}

				var conn net.Conn
				for i := range ip {
					conn, err = m.dialer.Dial("tcp", net.JoinHostPort(ip[i].String(), port))
					if err == nil {
						break
					}
				}
				return conn, err
			},
		},
	}

	m.packetConnMapper = [3]func(string) (net.PacketConn, error){
		m.proxyPacketa,
		blockPacket,
		func(s string) (net.PacketConn, error) {
			return net.ListenPacket("udp", "")
		},
	}
	return m, nil
}

func blockConn(s string) (net.Conn, error) {
	return nil, fmt.Errorf("block: %v", s)
}

func blockPacket(s string) (net.PacketConn, error) {
	return nil, fmt.Errorf("block: %v", s)
}

func (m *BypassManager) proxya(s string) (net.Conn, error) {
	return m.proxy(s)
}
func (m *BypassManager) proxyPacketa(s string) (net.PacketConn, error) {
	return m.proxyPacket(s)
}

// https://myexternalip.com/raw
func (m *BypassManager) Forward(host string) (conn net.Conn, err error) {
	mark, isIP, err := m.marry(host)
	if err != nil {
		return nil, fmt.Errorf("map failed: %v", err)
	}

	conn, err = m.connMapper[isIP][mark](host)
	return m.connManager.newConn(host, conn), err
}

func (m *BypassManager) ForwardPacket(host string) (conn net.PacketConn, err error) {
	mark, _, err := m.marry(host)
	if err != nil {
		return nil, fmt.Errorf("map failed: %v", err)
	}

	return m.packetConnMapper[mark](host)
}

//SetProxy .
func (m *BypassManager) SetProxy(conn func(string) (net.Conn, error),
	packetConn func(string) (net.PacketConn, error)) {
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
}

func (m *BypassManager) marry(host string) (mark, isIP int, err error) {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return 0, 0, fmt.Errorf("split host [%s] failed: %v", host, err)
	}

	if !m.bypass {
		mark = proxy
		if net.ParseIP(hostname) != nil {
			isIP = ip
		} else {
			isIP = domain
		}
	} else {
		mark, isIP = m.mapper(hostname)
	}

	fmt.Printf("[%s] ->  mode: %s\n", host, modeMapping[mark])

	return
}

func (m *BypassManager) GetDownload() uint64 {
	return m.connManager.GetDownload()
}

func (m *BypassManager) GetUpload() uint64 {
	return m.connManager.GetUpload()
}
