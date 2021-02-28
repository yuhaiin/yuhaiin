package app

import (
	"bufio"
	"bytes"
	_ "embed" //embed for bypass file
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	libDNS "github.com/Asutorufa/yuhaiin/net/dns"
	"github.com/Asutorufa/yuhaiin/net/match"
)

const (
	others  = 0
	mDirect = 1 << iota
	mProxy
	mIP
	mBlock
)

type bypass struct {
	enabled bool
	file    string
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
	bypass
	dns
	directDNS
	node

	matcher *match.Match

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

	m.matcher = match.NewMatch(func(argument *match.OptionArgument) {
		argument.DNS = option.DNS.Server
		argument.DOH = option.DNS.DOH
		argument.Subnet = option.DNS.Subnet
	})

	err := m.setBypass(bypassPath)
	if err != nil {
		return nil, err
	}

	m.enableDNSProxy(option.DNS.Proxy)
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
		BypassPath: m.bypass.file,
		Bypass:     m.bypass.enabled,
	}
	opt(option)

	m.setDNS(option.DNS.Server, option.DNS.DOH)
	m.setDirectDNS(option.DirectDNS.Server, option.DirectDNS.DOH)
	m.enableDNSProxy(option.DNS.Proxy)
	m.setDNSSubNet(option.DNS.Subnet)
	err := m.setBypass(option.BypassPath)
	m.bypass.enabled = option.Bypass
	return err
}

//go:embed yuhaiin.conf
var bypassData []byte

//RefreshMapping refresh data
func (m *BypassManager) RefreshMapping() error {
	f, err := os.Open(m.bypass.file)
	if err != nil && os.IsNotExist(err) {
		err = os.MkdirAll(path.Dir(m.bypass.file), os.ModePerm)
		if err != nil {
			return fmt.Errorf("UpdateMatch()MkdirAll -> %v", err)
		}
		f, err = os.OpenFile(m.bypass.file, os.O_TRUNC|os.O_CREATE|os.O_RDWR, os.ModePerm)
		if err != nil {
			return fmt.Errorf("UpdateMatch():OpenFile -> %v", err)
		}

		_, err = f.Write(bypassData)
		if err != nil {
			return fmt.Errorf("write bypass data failed: %v", err)
		}
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("open bypass file failed: %v", err)
	}
	defer f.Close()

	m.matcher.Clear()

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
		mode := m.mode(string(result[2]))
		if mode == others {
			continue
		}
		_ = m.matcher.Insert(string(result[1]), mode)
	}
	return nil
}

func (m *BypassManager) mode(str string) int {
	switch strings.ToLower(str) {
	case "direct":
		return mDirect
	case "proxy":
		return mProxy
	case "block":
		return mBlock
	case "ip":
		return mIP
	case "ipdirect":
		return mIP | mDirect
	default:
		return others
	}
}

var modeMapping = map[int]string{
	mDirect: "direct",
	mProxy:  "proxy",
	mBlock:  "block",
}

// https://myexternalip.com/raw
func (m *BypassManager) dial(network, host string) (conn interface{}, err error) {
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		return nil, fmt.Errorf("split host [%s] failed: %v", host, err)
	}

	md := m.matcher.Search(hostname)

	if md.Des == nil {
		fmt.Printf("[%s] -> %s, mode: default(proxy)\n", host, network)
	} else {
		fmt.Printf("[%s] -> %s, mode: %s\n", host, network, modeMapping[md.Des.(int)])
	}

	switch md.Category {
	case match.IP:
		conn, err = m.dialIP(network, host, md.Des)
	case match.DOMAIN:
		conn, err = m.dialDomain(network, hostname, port, md.Des)
	default:
		conn, err = m.proxy(host)
	}
	return conn, err
}

func (m *BypassManager) dialIP(network, host string, des interface{}) (conn interface{}, err error) {
	if des == mBlock {
		return nil, errors.New("block IP: " + host)
	}
	if des == mDirect {
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
	if des == mBlock {
		return nil, errors.New("block domain: " + hostname)
	}
	if des == mDirect {
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
		if err == nil {
			for i := range ip {
				conn, err = m.dialer.Dial("tcp", net.JoinHostPort(ip[i].String(), port))
				if err != nil {
					continue
				}
			}
		}
		if conn == nil {
			conn, err = m.dialer.Dial("tcp", net.JoinHostPort(hostname, port))
		}
	}

	if err != nil {
		return nil, fmt.Errorf("get packetConn failed: %v", err)
	}
	return
}

func (m *BypassManager) getIP(hostname string) (net.IP, error) {
	ips := m.matcher.GetIP(hostname)
	if len(ips) <= 0 {
		return nil, errors.New("not find")
	}
	return ips[0], nil
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
	m.setDNSProxy(m.dns.proxy)
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
	if m.bypass.enabled == b {
		if m.Forward == nil {
			m.setForward("tcp")
		}
		if m.ForwardPacket == nil {
			m.setForward("udp")
		}
		return
	}

	m.bypass.enabled = b
	switch b {
	case false:
		m.Forward = m.proxy
		m.ForwardPacket = m.ProxyPacket
	default:
		m.setForward("tcp")
		m.setForward("udp")
	}
}

func (m *BypassManager) setBypass(file string) error {
	if m.bypass.file == file {
		return nil
	}
	m.bypass.file = file
	return m.RefreshMapping()
}

/*
 *              DNS
 */
func (m *BypassManager) setDNS(server string, doh bool) {
	if m.dns.server == server && m.dns.doh == doh {
		return
	}
	m.dns.server = server
	m.dns.doh = doh
	m.matcher.SetDNS(server, doh)
}

func (m *BypassManager) setDNSProxy(enable bool) {
	if enable {
		m.dns.proxy = true
		m.matcher.SetDNSProxy(m.proxy)
	} else {
		m.dns.proxy = false
		m.matcher.SetDNSProxy(func(addr string) (net.Conn, error) {
			return net.DialTimeout("tcp", addr, 5*time.Second)
		})
	}
}

func (m *BypassManager) enableDNSProxy(enable bool) {
	if m.dns.proxy == enable {
		return
	}
	m.setDNSProxy(enable)
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

func (m *BypassManager) setDNSSubNet(ip *net.IPNet) {
	if m.matcher.DNS == nil || m.dns.Subnet == ip {
		return
	}
	m.dns.Subnet = ip
	m.matcher.DNS.SetSubnet(ip)
}

func (m *BypassManager) GetDownload() uint64 {
	return m.connManager.download
}

func (m *BypassManager) GetUpload() uint64 {
	return m.connManager.upload
}

type connManager struct {
	conns    sync.Map
	id       uint64
	download uint64
	upload   uint64

	queue         chan *statisticConn
	downloadQueue chan uint64
	uploadQueue   chan uint64
}

func newConnManager() *connManager {
	c := &connManager{
		id:       0,
		download: 0,
		upload:   0,

		queue:         make(chan *statisticConn, 5),
		downloadQueue: make(chan uint64, 5),
		uploadQueue:   make(chan uint64, 5),
	}

	c.startQueue()

	return c
}

func (c *connManager) startQueue() {
	go func() {
		for s := range c.queue {
			s.id = c.id
			c.conns.Store(c.id, s)
			atomic.AddUint64(&c.id, 1)
		}
	}()

	go func() {
		for s := range c.downloadQueue {
			atomic.AddUint64(&c.download, s)
		}
	}()

	go func() {
		for s := range c.uploadQueue {
			atomic.AddUint64(&c.upload, s)
		}
	}()
}

func (c *connManager) add(i *statisticConn) {
	go func() {
		c.queue <- i
	}()
}

func (c *connManager) delete(id uint64) {
	v, _ := c.conns.LoadAndDelete(id)
	if x, ok := v.(*statisticConn); ok {
		fmt.Printf("close id: %d,addr: %s\n", x.id, x.addr)
	}
}

func (c *connManager) addDownload(i uint64) {
	go func() {
		c.downloadQueue <- i
	}()
}

func (c *connManager) addUpload(i uint64) {
	go func() {
		c.uploadQueue <- i
	}()
}

func (c *connManager) Write(b []byte, w io.Writer) (int, error) {
	n, err := w.Write(b)
	c.addUpload(uint64(n))
	return n, err
}

func (c *connManager) Read(b []byte, r io.Reader) (int, error) {
	n, err := r.Read(b)
	c.addDownload(uint64(n))
	return n, err

}

func (c *connManager) newConn(addr string, x net.Conn) net.Conn {
	s := &statisticConn{
		addr: addr,
		Conn: x,
	}
	s.close = func() error {
		c.delete(s.id)
		return s.Conn.Close()
	}

	s.write = func(b []byte) (int, error) {
		n, err := s.Conn.Write(b)
		c.addUpload(uint64(n))
		return n, err
	}

	s.read = func(b []byte) (int, error) {
		n, err := s.Conn.Read(b)
		c.addDownload(uint64(n))
		return n, err
	}

	c.add(s)

	return s
}

type statisticConn struct {
	net.Conn
	close func() error
	write func([]byte) (int, error)
	read  func([]byte) (int, error)

	id   uint64
	addr string
}

func (s *statisticConn) Close() error {
	return s.close()
}

func (s *statisticConn) Write(b []byte) (int, error) {
	return s.write(b)
}

func (s *statisticConn) Read(b []byte) (int, error) {
	return s.read(b)
}
