package app

import (
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"

	"github.com/Asutorufa/yuhaiin/internal/app/component"
)

//BypassManager .
type BypassManager struct {
	lookup      func(string) ([]net.IP, error)
	mapper      component.Mapper
	proxy       utils.Proxy
	dialer      net.Dialer
	connManager *connManager

	/*
	 * type\mark  others direct block
	 *	IP
	 * DOMAIN
	 */
	connMapper       [2][3]func(string) (net.Conn, error)
	packetConnMapper [3]func(string) (net.PacketConn, error)
}

//NewBypassManager .
func NewBypassManager(mapper component.Mapper, lookup func(string) ([]net.IP, error)) (*BypassManager, error) {
	if mapper == nil {
		fmt.Println("checked mapper is nil, disable bypass.")
	}
	if lookup == nil {
		lookup = net.LookupIP
	}

	m := &BypassManager{
		dialer:      net.Dialer{Timeout: 11 * time.Second},
		lookup:      lookup,
		proxy:       &utils.DefaultProxy{},
		mapper:      mapper,
		connManager: newConnManager(),
	}

	m.connMapper = [2][3]func(string) (net.Conn, error){
		/*
		 * +---------+------+-----+------+
		 * |type\mark|others|block|direct|
		 * +---------+------+-----+------+
		 * |   IP    |      |     |      |
		 * +---------+------+-----+------+
		 * | DOMAIN  |      |     |      |
		 * +---------+------+-----+------+
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
	/*
	* +----+------+-----+------+
	* |mark|others|block|direct|
	* +----+------+-----+------+
	* |----|      |     |      |
	* +----+------+-----+------+
	 */
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
	return m.proxy.Conn(s)
}
func (m *BypassManager) proxyPacketa(s string) (net.PacketConn, error) {
	return m.proxy.PacketConn(s)
}

//Forward get net.Conn by host
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
func (m *BypassManager) SetProxy(p utils.Proxy) {
	if p == nil {
		m.proxy = &utils.DefaultProxy{}
	} else {
		m.proxy = p
	}
}

func (m *BypassManager) marry(host string) (mark component.MODE, isIP component.RespType, err error) {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return 0, 0, fmt.Errorf("split host [%s] failed: %v", host, err)
	}

	if m.mapper == nil {
		mark = component.OTHERS
		if net.ParseIP(hostname) != nil {
			isIP = component.IP
		} else {
			isIP = component.DOMAIN
		}
	} else {
		s := m.mapper.Get(hostname)
		mark = s.Mark
		isIP = s.IP
	}

	fmt.Printf("[%s] ->  mode: %s\n", host, component.ModeMapping[mark])

	return
}

func (m *BypassManager) GetDownload() uint64 {
	return m.connManager.GetDownload()
}

func (m *BypassManager) GetUpload() uint64 {
	return m.connManager.GetUpload()
}
