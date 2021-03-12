package app

import (
	"bufio"
	"bytes"
	_ "embed" //embed for bypass file
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	libDNS "github.com/Asutorufa/yuhaiin/net/dns"
	mapper "github.com/Asutorufa/yuhaiin/net/mapper"
)

const (
	others = 0
	direct = 1 << iota
	proxy
	ip
	block
)

//go:embed yuhaiin.conf
var bypassData []byte

var modeMapping = map[int]string{
	direct: "direct",
	proxy:  "proxy",
	block:  "block",
}

var mode = map[string]int{
	"direct":   direct,
	"proxy":    proxy,
	"block":    block,
	"ip":       ip,
	"ipdirect": ip | direct,
}

type dns struct {
	server string
	doh    bool
	proxy  bool
	Subnet *net.IPNet
}

type directDNS struct {
	dns    libDNS.DNS
	server string
	doh    bool
}

type node struct {
	hash string
}

//BypassManager .
type BypassManager struct {
	bypass bool
	dns
	directDNS
	node

	*shunt

	Forward       func(string) (net.Conn, error)
	ForwardPacket func(string) (net.PacketConn, error)
	proxy         func(string) (net.Conn, error)
	ProxyPacket   func(string) (net.PacketConn, error)

	dialer      net.Dialer
	connManager *connManager
}

//OptionBypassManager create bypass manager options
type OptionBypassManager struct {
	DNS struct {
		Server string
		DOH    bool
		Proxy  bool
		Subnet *net.IPNet
	}
	DirectDNS struct {
		Server string
		DOH    bool
	}
	BypassPath string
	Bypass     bool
}

//NewBypassManager .
func NewBypassManager(bypassPath string, opt ...func(option *OptionBypassManager)) (*BypassManager, error) {
	m := &BypassManager{
		dialer: net.Dialer{
			Timeout: 15 * time.Second,
		},
		directDNS: directDNS{libDNS.NewDOH("223.5.5.5"), "223.5.5.5", true},
		proxy: func(host string) (conn net.Conn, err error) {
			return net.DialTimeout("tcp", host, 15*time.Second)
		},
		ProxyPacket: func(s string) (net.PacketConn, error) {
			return net.ListenPacket("udp", "")
		},

		connManager: newConnManager(),
	}

	option := &OptionBypassManager{}
	for i := range opt {
		opt[i](option)
	}

	var err error
	m.shunt, err = NewShunt(bypassPath, getDNS(option.DNS.Server, option.DNS.DOH).Search)
	if err != nil {
		return nil, fmt.Errorf("set bypass failed: %v", err)
	}

	m.setMode(option.Bypass)

	return m, nil
}

//SetAllOption set bypass manager config
func (m *BypassManager) SetAllOption(opt func(option *OptionBypassManager)) error {
	if opt == nil {
		return nil
	}
	option := &OptionBypassManager{
		DNS: struct {
			Server string
			DOH    bool
			Proxy  bool
			Subnet *net.IPNet
		}{
			Server: m.dns.server,
			DOH:    m.dns.doh,
			Proxy:  m.dns.proxy,
			Subnet: m.dns.Subnet,
		},
		DirectDNS: struct {
			Server string
			DOH    bool
		}{Server: m.directDNS.server, DOH: m.directDNS.doh},
		Bypass: m.bypass,
	}
	opt(option)

	m.setDNS(option.DNS.Server, option.DNS.DOH)
	m.setDirectDNS(option.DirectDNS.Server, option.DirectDNS.DOH)
	m.setMode(option.Bypass)

	return m.shunt.SetFile(option.BypassPath)
}

// https://myexternalip.com/raw
func (m *BypassManager) dial(network, host string) (conn interface{}, err error) {
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		return nil, fmt.Errorf("split host [%s] failed: %v", host, err)
	}

	mark, markType := m.shunt.Get(hostname)

	if mark == others {
		fmt.Printf("[%s] -> %s, mode: default(proxy)\n", host, network)
	} else {
		fmt.Printf("[%s] -> %s, mode: %s\n", host, network, modeMapping[mark])
	}

	switch markType {
	case mapper.IP:
		conn, err = m.dialIP(network, host, mark)
	case mapper.DOMAIN:
		conn, err = m.dialDomain(network, hostname, port, mark)
	default:
		conn, err = m.proxy(host)
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
		return m.ProxyPacket(host)
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
		return m.ProxyPacket(net.JoinHostPort(hostname, port))
	}
	return m.proxy(net.JoinHostPort(hostname, port))
_direct:
	switch network {
	case "udp":
		conn, err = net.ListenPacket("udp", "")
	default:
		ip, err := m.directDNS.dns.Search(hostname)
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

/*
 *     node Control
 */

//SetProxy .
func (m *BypassManager) SetProxy(
	conn func(string) (net.Conn, error),
	packetConn func(string) (net.PacketConn, error),
	hash string,
) {
	if m.node.hash == hash {
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
		m.ProxyPacket = func(s string) (net.PacketConn, error) {
			return net.ListenPacket("udp", "")
		}
	} else {
		m.ProxyPacket = packetConn
	}

	m.node.hash = hash
}

/**
*  Set
 */

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

func (m *BypassManager) setMode(b bool) {
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
		m.ForwardPacket = m.ProxyPacket
	default:
		m.setForward("tcp")
		m.setForward("udp")
	}
}

/*
 *              DNS
 */
func (m *BypassManager) setDNS(server string, doh bool) {
	if m.dns.server == server && m.dns.doh == doh {
		return
	}
	m.shunt.SetLookup(getDNS(m.dns.server, m.dns.doh).Search)
}

func getDNS(host string, doh bool) libDNS.DNS {
	if doh {
		return libDNS.NewDNS(host, libDNS.DNSOverHTTPS)
	}
	return libDNS.NewDNS(host, libDNS.Normal)
}

func (m *BypassManager) setDirectDNS(server string, doh bool) {
	if m.directDNS.server == server && m.directDNS.doh == doh {
		return
	}
	m.directDNS.server = server
	m.directDNS.doh = doh

	if doh {
		m.directDNS.dns = libDNS.NewDOH(server)
	} else {
		m.directDNS.dns = libDNS.NewNormalDNS(server)
	}
}

func (m *BypassManager) GetDownload() uint64 {
	return m.connManager.download
}

func (m *BypassManager) GetUpload() uint64 {
	return m.connManager.upload
}

type shunt struct {
	file   string
	mapper *mapper.Mapper
}

//NewShunt file: bypass file; lookup: domain resolver, can be nil
func NewShunt(file string, lookup func(string) ([]net.IP, error)) (*shunt, error) {
	s := &shunt{
		file:   file,
		mapper: mapper.NewMapper(lookup),
	}
	err := s.RefreshMapping()
	if err != nil {
		return nil, fmt.Errorf("refresh mapping failed: %v", err)
	}
	return s, nil
}

func (s *shunt) RefreshMapping() error {
	log.Println(s.file)
	_, err := os.Stat(s.file)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(path.Dir(s.file), os.ModePerm)
		if err != nil {
			return fmt.Errorf("make dir all failed: %v", err)
		}
		err = ioutil.WriteFile(s.file, bypassData, os.ModePerm)
		if err != nil {
			return fmt.Errorf("write bypass file failed: %v", err)
		}
	}

	f, err := os.Open(s.file)
	if err != nil {
		return fmt.Errorf("open bypass file failed: %v", err)
	}
	defer f.Close()

	s.mapper.Clear()

	re, _ := regexp.Compile("^([^ ]+) +([^ ]+) *$") // already test that is right regular expression, so don't need to check error
	br := bufio.NewReader(f)
	for {
		a, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		if bytes.HasPrefix(a, []byte("#")) {
			continue
		}
		result := re.FindSubmatch(a)
		if len(result) != 3 {
			continue
		}
		mode := mode[strings.ToLower(string(result[2]))]
		if mode == others {
			continue
		}
		_ = s.mapper.Insert(string(result[1]), mode)
	}
	return nil
}

func (s *shunt) SetFile(f string) error {
	if s.file == f {
		return nil
	}
	s.file = f
	return s.RefreshMapping()
}

func (s *shunt) Get(domain string) (int, mapper.Category) {
	mark, markType := s.mapper.Search(domain)
	x, ok := mark.(int)
	if !ok {
		return others, markType
	}
	return x, markType
}

func (s *shunt) SetLookup(f func(string) ([]net.IP, error)) {
	s.mapper.SetLookup(f)
}
