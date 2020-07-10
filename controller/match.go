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

var (
	bypass       = 0
	globalDirect = 1
	globalProxy  = 2
)

type todo int

var (
	others   todo = 0
	direct   todo = 1
	proxy    todo = 2
	IP       todo = 3
	block    todo = 4
	ipDirect todo = 5
	modes         = map[string]todo{"direct": direct, "proxy": proxy, "block": block, "ip": IP, "ipdirect": ipDirect}
)

type insertData struct {
	Type  todo
	other string
}

//var (
//	Proxy = func(host string) (conn net.Conn, err error) { return net.DialTimeout("tcp", host, time.Second*7) }
//)

type MatchController struct {
	bypass     bool
	dNSProxy   bool
	bypassFile string
	Matcher    *match.Match
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
}
type MatchConOption func(option *OptionMatchCon)

func NewMatchCon(bypassPath string, modOption ...MatchConOption) (*MatchController, error) {
	m := &MatchController{}
	m.Matcher = match.NewMatch()
	m.proxy = func(host string) (conn net.Conn, err error) { return net.DialTimeout("tcp", host, 5*time.Second) }
	err := m.SetBypass(bypassPath)
	if err != nil {
		return nil, err
	}
	option := &OptionMatchCon{}
	for index := range modOption {
		modOption[index](option)
	}
	if option.DNS.Server != "" {
		m.SetDNS(option.DNS.Server, option.DNS.DOH)
		m.EnableDNSProxy(option.DNS.Proxy)
		m.SetDNSSubNet(option.DNS.Subnet)
	}
	m.bypass = option.Bypass
	return m, nil
}

func (m *MatchController) SetAllOption(modeOption MatchConOption) error {
	if modeOption == nil {
		return nil
	}
	option := &OptionMatchCon{}
	modeOption(option)

	m.SetDNS(option.DNS.Server, option.DNS.DOH)
	m.EnableDNSProxy(option.DNS.Proxy)
	m.SetDNSSubNet(option.DNS.Subnet)
	err := m.SetBypass(option.BypassPath)
	return err
}

func (m *MatchController) EnableDNSProxy(enable bool) {
	if m.dNSProxy == enable {
		return
	}
	if enable {
		m.dNSProxy = true
		m.Matcher.DNS.SetProxy(m.proxy)
	} else {
		m.dNSProxy = false
		m.Matcher.DNS.SetProxy(func(addr string) (net.Conn, error) {
			return net.DialTimeout("tcp", addr, 5*time.Second)
		})
	}
}

func (m *MatchController) EnableBYPASS(enable bool) {
	m.bypass = enable
}

func (m *MatchController) SetProxy(proxy func(host string) (net.Conn, error)) {
	m.proxy = proxy
	if m.dNSProxy {
		m.EnableDNSProxy(true)
	}
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
		err = m.Matcher.Insert(domain, modes[strings.ToLower(mode)])
		if err != nil {
			continue
		}
	}
	return nil
}

func (m *MatchController) SetBypass(file string) error {
	if m.bypassFile == file {
		return nil
	}
	m.bypassFile = file
	return m.UpdateMatch()
}

func (m *MatchController) SetDNS(server string, doh bool) {
	m.Matcher.SetDNS(server, doh)
}

func (m *MatchController) SetDNSSubNet(ip *net.IPNet) {
	if m.Matcher.DNS == nil {
		return
	}
	m.Matcher.DNS.SetSubnet(ip)
}

// https://myexternalip.com/raw
func (m *MatchController) Forward(host string) (conn net.Conn, err error) {
	if !m.bypass {
		return m.proxy(host)
	}

	var URI *url.URL
	var md match.Des

	URI, err = url.Parse("//" + host)
	if err != nil {
		goto _proxy
	}

	md = m.Matcher.Search(URI.Hostname())

	switch md.Des {
	case direct:
		goto _direct
	case proxy:
		goto _proxy
	case block:
		return nil, errors.New("block domain: " + host)
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
		host = net.JoinHostPort(ip.String(), URI.Port())

		switch md.Des {
		case ipDirect:
			//log.Println(tmp, "IPDIRECT", host)
			//log.Println(m.Matcher.DNS.GetSubnet().IP, m.Matcher.DNS.GetSubnet().Mask)
			goto _direct
		case IP:
			goto _proxy
		}
	}

_proxy:
	return m.proxy(host)
_direct:
	return net.DialTimeout("tcp", host, 5*time.Second)
}

func (m *MatchController) getIP(hostname string) (net.IP, error) {
	ips := m.Matcher.GetIP(hostname)
	if len(ips) <= 0 {
		return nil, errors.New("not find")
	}
	return ips[0], nil
}
