package MatchAndForward

import (
	config2 "SsrMicroClient/config"
	"SsrMicroClient/net/dns"
	getproxyconn "SsrMicroClient/net/forward"
	"SsrMicroClient/net/matcher"
	socks5client "SsrMicroClient/net/proxy/socks5/client"
	"context"
	"errors"
	"log"
	"net"
	"net/url"
)

type ForwardTo struct {
	Matcher *matcher.Match
	Config  *config2.ConfigSample
	Setting *config2.Setting
	Log     func(v ...interface{})
}

func NewForwardTo(configJsonPath, rulePath string) (forwardTo *ForwardTo, err error) {
	forwardTo = &ForwardTo{}
	forwardTo.Setting, err = config2.SettingDecodeJSON(configJsonPath)
	if err != nil {
		return
	}

	var dnsFunc func(domain string) (DNS []string, success bool)
	switch forwardTo.Setting.IsDNSOverHTTPS {
	case true:
		if forwardTo.Setting.DNSAcrossProxy {
			proxy := func(ctx context.Context, network, addr string) (net.Conn, error) {
				x := &socks5client.Socks5Client{Server: forwardTo.Setting.LocalAddress, Port: forwardTo.Setting.LocalPort, Address: addr}
				return x.NewSocks5Client()
			}
			dnsFunc = func(domain string) (DNS []string, success bool) {
				return dns.DNSOverHTTPS(forwardTo.Setting.DnsServer, domain, proxy)
			}
		} else {
			dnsFunc = func(domain string) (DNS []string, success bool) {
				return dns.DNSOverHTTPS(forwardTo.Setting.DnsServer, domain, nil)
			}
		}
	case false:
		dnsFunc = func(domain string) (DNS []string, success bool) {
			return dns.DNS(forwardTo.Setting.DnsServer, domain)
		}
	}
	forwardTo.Matcher, err = matcher.NewMatcherWithFile(dnsFunc, rulePath)
	if err != nil {
		log.Println(err, rulePath)
	}
	return
}

func (ForwardTo *ForwardTo) log(v ...interface{}) {
	if ForwardTo.Log != nil {
		ForwardTo.Log(v)
	} else {
		log.Println(v...)
	}
}

func (ForwardTo *ForwardTo) Forward(host string) (conn net.Conn, err error) {
	var URI *url.URL
	var proxyURI *url.URL
	var proxy string
	var mode string
	if URI, err = url.Parse("//" + host); err != nil {
		return nil, err
	}
	if URI.Port() == "" {
		host = net.JoinHostPort(host, "80")
		if URI, err = url.Parse("//" + host); err != nil {
			return nil, err
		}
	}

	switch ForwardTo.Matcher {
	default:
		hosts, proxy := ForwardTo.Matcher.MatchStr(URI.Hostname())
		if proxy == "block" {
			return nil, errors.New("block domain: " + host)
		} else if proxy == "direct" {
			proxyURI, err = url.Parse("direct://0.0.0.0:0")
			if err != nil {
				return nil, err
			}
		} else if proxy == "proxy" {
			proxyURI, err = url.Parse("socks5://" + ForwardTo.Setting.LocalAddress + ":" + ForwardTo.Setting.LocalPort)
			if err != nil {
				return nil, err
			}
			if ForwardTo.Setting.IsPrintLog {
				ForwardTo.log("Mode: " + mode + " | Domain: " + host + " | match to " + proxy)
			}
			return getproxyconn.ForwardTo(host, *proxyURI)
		} else {
			proxy = "default"
			proxyURI, err = url.Parse("socks5://" + ForwardTo.Setting.LocalAddress + ":" + ForwardTo.Setting.LocalPort)
			if err != nil {
				return nil, err
			}
		}
		for x := range hosts {
			host = net.JoinHostPort(hosts[x], URI.Port())
			conn, err = getproxyconn.ForwardTo(host, *proxyURI)
			if err == nil {
				if ForwardTo.Setting.IsPrintLog {
					ForwardTo.log("Mode: " + mode + " | Domain: " + host + " | match to " + proxy)
				}
				return conn, nil
			}
		}
		return nil, errors.New("make connection:" + net.JoinHostPort(hosts[len(hosts)-1], URI.Port()) + " with proxy:" + proxy + " error")
	case nil:
		proxy = "Direct"
		proxyURI, err = url.Parse("direct://0.0.0.0:0")
		if err != nil {
			return nil, err
		}
	}
	if ForwardTo.Setting.IsPrintLog {
		ForwardTo.log("Mode: " + mode + " | Domain: " + host + " | match to " + proxy)
	}
	conn, err = getproxyconn.ForwardTo(host, *proxyURI)
	return
}
