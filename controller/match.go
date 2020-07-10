package controller

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/net/match"
)

const (
	others  = 0
	mDirect = 1 << iota
	mProxy
	mIP
	mBlock
)

type MatchController struct {
	bypass bool
	dns    struct {
		server string
		doh    bool
		Proxy  bool
		Subnet *net.IPNet
	}
	bypassFile string
	matcher    *match.Match
	proxy      func(host string) (conn net.Conn, err error)
}

type OptionMatchCon struct {
	DNS struct {
		Server string
		DOH    bool
		Proxy  bool
		Subnet *net.IPNet
	}
	BypassPath string
	Bypass     bool
	Proxy      func(string) (net.Conn, error)
}
type MatchConOption func(option *OptionMatchCon)

func NewMatchCon(bypassPath string, modOption ...MatchConOption) (*MatchController, error) {
	m := &MatchController{}
	option := &OptionMatchCon{
		Proxy: func(s string) (net.Conn, error) {
			return net.DialTimeout("tcp", s, 5*time.Second)
		},
	}
	for index := range modOption {
		modOption[index](option)
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
	m.setProxy(option.Proxy)
	m.bypass = option.Bypass
	return m, nil
}

func (m *MatchController) SetAllOption(modeOption MatchConOption) error {
	if modeOption == nil {
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
			Proxy:  m.dns.Proxy,
			Subnet: m.dns.Subnet,
		},
		BypassPath: m.bypassFile,
		Bypass:     m.bypass,
	}
	modeOption(option)

	m.setDNS(option.DNS.Server, option.DNS.DOH)
	m.enableDNSProxy(option.DNS.Proxy)
	m.setDNSSubNet(option.DNS.Subnet)
	m.setProxy(option.Proxy)
	err := m.setBypass(option.BypassPath)
	m.bypass = option.Bypass
	return err
}

func (m *MatchController) enableDNSProxy(enable bool) {
	if m.dns.Proxy == enable {
		return
	}
	m.setDNSProxy(enable)
}

func (m *MatchController) setDNSProxy(enable bool) {
	if enable {
		m.dns.Proxy = true
		m.matcher.SetDNSProxy(m.proxy)
	} else {
		m.dns.Proxy = false
		m.matcher.SetDNSProxy(func(addr string) (net.Conn, error) {
			return net.DialTimeout("tcp", addr, 5*time.Second)
		})
	}
}

func (m *MatchController) setBypass(file string) error {
	if m.bypassFile == file {
		return nil
	}
	m.bypassFile = file
	return m.UpdateMatch()
}

func (m *MatchController) setDNS(server string, doh bool) {
	if m.dns.server == server && m.dns.doh == doh {
		return
	}
	m.dns.server = server
	m.dns.doh = doh
	m.matcher.SetDNS(server, doh)
}

func (m *MatchController) setDNSSubNet(ip *net.IPNet) {
	if m.matcher.DNS == nil || m.dns.Subnet == ip {
		return
	}
	m.dns.Subnet = ip
	m.matcher.DNS.SetSubnet(ip)
}

func (m *MatchController) setProxy(proxy func(host string) (net.Conn, error)) {
	if proxy == nil {
		return
	}
	m.proxy = proxy
	m.setDNSProxy(m.dns.Proxy)
}

func (m *MatchController) UpdateMatch() error {
	f, err := os.Open(m.bypassFile)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(path.Dir(m.bypassFile), os.ModePerm)
			if err != nil {
				return fmt.Errorf("UpdateMatch()MkdirAll -> %v", err)
			}
			f, err = os.OpenFile(m.bypassFile, os.O_TRUNC|os.O_CREATE|os.O_RDWR, os.ModePerm)
			if err != nil {
				return fmt.Errorf("UpdateMatch():OpenFile -> %v", err)
			}
			res, err := http.Get("https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/ACL/yuhaiin/yuhaiin.conf")
			if err != nil {
				return err
			}
			_, _ = io.Copy(f, res.Body)
		}
		return err
	}
	defer f.Close()

	var domain string
	var mode string
	br := bufio.NewReader(f)
	for {
		a, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		_, err = fmt.Sscanf(string(a), "%s %s", &domain, &mode)
		if err != nil {
			continue
		}
		err = m.matcher.Insert(domain, m.mode(mode))
		if err != nil {
			continue
		}
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
		return 0
	}
}

// https://myexternalip.com/raw
func (m *MatchController) Forward(host string) (conn net.Conn, err error) {
	if !m.bypass {
		return m.proxy(host)
	}

	URI, err := url.Parse("//" + host)
	if err != nil {
		return m.proxy(host)
	}

	return m.forward(m.matcher.Search(URI.Hostname()), URI)
}

func (m *MatchController) forward(md match.Des, URI *url.URL) (net.Conn, error) {
	switch md.Des {
	case mDirect:
		goto _direct
	case mProxy:
		goto _proxy
	case mBlock:
		return nil, errors.New("block domain: " + URI.Host)
	}

	{
		// need to get IP from DNS
		var ip net.IP
		if len(md.DNS) > 0 {
			ip = md.DNS[0]
		} else {
			ip, _ = m.getIP(URI.Hostname())
		}
		if ip == nil {
			goto _proxy
		}
		URI.Host = net.JoinHostPort(ip.String(), URI.Port())

		switch md.Des {
		case mIP | mDirect:
			goto _direct
		case mIP:
			goto _proxy
		}
	}

_proxy:
	return m.proxy(URI.Host)
_direct:
	return net.DialTimeout("tcp", URI.Host, 5*time.Second)
}

func (m *MatchController) getIP(hostname string) (net.IP, error) {
	ips := m.matcher.GetIP(hostname)
	if len(ips) <= 0 {
		return nil, errors.New("not find")
	}
	return ips[0], nil
}
