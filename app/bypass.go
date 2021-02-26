package app

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
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

type MatchController struct {
	bypass
	dns
	directDNS
	node
	matcher     *match.Match
	Forward     func(string) (net.Conn, error)
	proxy       func(host string) (conn net.Conn, err error)
	packetProxy func(string) (net.PacketConn, error)
	dialer      net.Dialer
}

type OptionMatchCon struct {
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
type MatchConOption func(option *OptionMatchCon)

func NewMatchCon(bypassPath string, opt ...MatchConOption) (*MatchController, error) {
	m := &MatchController{
		dialer: net.Dialer{
			Timeout: 15 * time.Second,
		},
		directDNS: directDNS{libDNS.NewDOH("223.5.5.5"), "223.5.5.5", true},
		proxy: func(host string) (conn net.Conn, err error) {
			return net.DialTimeout("tcp", host, 15*time.Second)
		},
	}
	option := &OptionMatchCon{}
	for index := range opt {
		opt[index](option)
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

func (m *MatchController) SetAllOption(opt MatchConOption) error {
	if opt == nil {
		return nil
	}
	option := &OptionMatchCon{
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

func (m *MatchController) setMode(b bool) {
	if m.bypass.enabled == b {
		if m.Forward == nil {
			m.Forward = m.dial
		}
		return
	}
	m.bypass.enabled = b
	switch b {
	case false:
		m.Forward = m.proxy
	default:
		m.Forward = m.dial
	}
}

func (m *MatchController) setBypass(file string) error {
	if m.bypass.file == file {
		return nil
	}
	m.bypass.file = file
	return m.UpdateMatch()
}

func (m *MatchController) UpdateMatch() error {
	f, err := os.Open(m.bypass.file)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(path.Dir(m.bypass.file), os.ModePerm)
			if err != nil {
				return fmt.Errorf("UpdateMatch()MkdirAll -> %v", err)
			}
			f, err = os.OpenFile(m.bypass.file, os.O_TRUNC|os.O_CREATE|os.O_RDWR, os.ModePerm)
			if err != nil {
				return fmt.Errorf("UpdateMatch():OpenFile -> %v", err)
			}
			goto _local

		_local:
			var execPath string
			var data *os.File
			file, err := exec.LookPath(os.Args[0])
			if err != nil {
				log.Println(err)
				goto _net
			}
			execPath, err = filepath.Abs(file)
			if err != nil {
				log.Println(err)
				goto _net
			}
			data, err = os.Open(path.Join(filepath.Dir(execPath), "static/yuhaiin.conf"))
		_net:
			if err != nil {
				log.Println(err)
				res, err := http.Get("https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/ACL/yuhaiin/yuhaiin.conf")
				if err != nil {
					return err
				}
				_, _ = io.Copy(f, res.Body)
			} else {
				_, _ = io.Copy(f, data)
			}
		} else {
			return err
		}
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

func (m *MatchController) mode(str string) int {
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

// https://myexternalip.com/raw
func (m *MatchController) dial(host string) (conn net.Conn, err error) {
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		return nil, err
	}
	md := m.matcher.Search(hostname)

	switch md.Category {
	case match.IP:
		return m.dialIP(host, md.Des)
	case match.DOMAIN:
		return m.dialDomain(hostname, port, md.Des)
	}
	return m.proxy(host)
}

func (m *MatchController) dialPacket(host string) (conn net.PacketConn, err error) {
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		return nil, err
	}
	md := m.matcher.Search(hostname)

	switch md.Category {
	case match.IP:
		// return m.dialIP(host, md.Des)
		return m.dialPacketIP(host, md.Des)
	case match.DOMAIN:
		// return m.dialDomain(hostname, port, md.Des)
		return m.dialPacketDomain(hostname, port, md.Des)
	}
	return m.packetProxy(host)
}

func (m *MatchController) dialIP(host string, des interface{}) (net.Conn, error) {
	switch des {
	default:
		goto _proxy
	case mDirect:
		goto _direct
	case mBlock:
		return nil, errors.New("block domain: " + host)
	}

_proxy:
	return m.proxy(host)
_direct:
	conn, err := m.dialer.Dial("tcp", host)
	if err != nil {
		return nil, fmt.Errorf("match direct -> %v", err)
	}
	return conn, err
}

func (m *MatchController) dialPacketDomain(hostname, port string, des interface{}) (net.PacketConn, error) {

	switch des {
	default:
		goto _proxy
	case mDirect:
		goto _direct
	case mBlock:
		return nil, errors.New("block domain: " + hostname)
	}

_proxy:
	return m.packetProxy(net.JoinHostPort(hostname, port))
_direct:
	return net.ListenPacket("udp", "")
	// ip, err := m.directDNS.dns.Search(hostname)
	// if err != nil {
	// return nil, err
	// }
	//fmt.Println(hostname, ip)
	// for index := range ip {
	// conn, err := m.dialer.Dial("tcp", net.JoinHostPort(ip[index].String(), port))
	// if err != nil {
	// continue
	// }
	// return conn, nil
	// }
	// return m.dialer.Dial("tcp", net.JoinHostPort(hostname, port))
}

func (m *MatchController) dialPacketIP(host string, des interface{}) (net.PacketConn, error) {
	switch des {
	default:
		goto _proxy
	case mDirect:
		goto _direct
	case mBlock:
		return nil, errors.New("block domain: " + host)
	}

_proxy:
	return m.packetProxy(host)
_direct:
	conn, err := net.ListenPacket("udp", "")
	// conn, err := m.dialer.dialPacket("tcp", host)
	if err != nil {
		return nil, fmt.Errorf("match direct -> %v", err)
	}
	return conn, err
}

func (m *MatchController) dialDomain(hostname, port string, des interface{}) (net.Conn, error) {

	switch des {
	default:
		goto _proxy
	case mDirect:
		goto _direct
	case mBlock:
		return nil, errors.New("block domain: " + hostname)
	}

_proxy:
	return m.proxy(net.JoinHostPort(hostname, port))
_direct:
	ip, err := m.directDNS.dns.Search(hostname)
	if err != nil {
		return nil, err
	}
	//fmt.Println(hostname, ip)
	for index := range ip {
		conn, err := m.dialer.Dial("tcp", net.JoinHostPort(ip[index].String(), port))
		if err != nil {
			continue
		}
		return conn, nil
	}
	return m.dialer.Dial("tcp", net.JoinHostPort(hostname, port))
}

func (m *MatchController) getIP(hostname string) (net.IP, error) {
	ips := m.matcher.GetIP(hostname)
	if len(ips) <= 0 {
		return nil, errors.New("not find")
	}
	return ips[0], nil
}

/*
 *              DNS
 */
func (m *MatchController) setDNS(server string, doh bool) {
	if m.dns.server == server && m.dns.doh == doh {
		return
	}
	m.dns.server = server
	m.dns.doh = doh
	m.matcher.SetDNS(server, doh)
}

func (m *MatchController) setDNSProxy(enable bool) {
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

func (m *MatchController) enableDNSProxy(enable bool) {
	if m.dns.proxy == enable {
		return
	}
	m.setDNSProxy(enable)
}

func (m *MatchController) setDirectDNS(server string, doh bool) {
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

func (m *MatchController) setDNSSubNet(ip *net.IPNet) {
	if m.matcher.DNS == nil || m.dns.Subnet == ip {
		return
	}
	m.dns.Subnet = ip
	m.matcher.DNS.SetSubnet(ip)
}

/*
 *     node Control
 */
func (m *MatchController) ChangeNode(conn func(string) (net.Conn, error), hash string) {
	if m.node.hash == hash {
		return
	}
	if conn == nil {
		return
	}
	m.node.hash = hash
	m.proxy = conn
	m.setDNSProxy(m.dns.proxy)
}
