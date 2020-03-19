package MatchAndForward

import (
	"context"
	"errors"
	"log"
	"net"
	"net/url"

	"SsrMicroClient/config"
	"SsrMicroClient/net/dns"
	"SsrMicroClient/net/forward"
	"SsrMicroClient/net/matcher"
	"SsrMicroClient/net/proxy/socks5/client"
)

type ForwardFunc struct {
	dnsCache *dns.Cache
	Matcher  *matcher.Match
	Config   *config.ConfigSample
	Setting  *config.Setting
	Log      func(v ...interface{})
}

func NewForwardFunc(configJsonPath, rulePath string) (forwardFunc *ForwardFunc, err error) {
	forwardFunc = &ForwardFunc{dnsCache: dns.NewDnsCache()}
	forwardFunc.Setting, err = config.SettingDecodeJSON(configJsonPath)
	if err != nil {
		return
	}

	forwardFunc.Matcher, err = matcher.NewMatcherWithFile(dnsFunc(forwardFunc), rulePath)
	if err != nil {
		log.Println(err, rulePath)
	}
	return
}

func dnsFunc(f *ForwardFunc) func(domain string) (DNS []string, success bool) {
	var dnsFuncParent func(domain string) (DNS []string, success bool)
	switch f.Setting.IsDNSOverHTTPS {
	case true:
		if f.Setting.DNSAcrossProxy {
			proxy := func(ctx context.Context, network, addr string) (net.Conn, error) {
				x := &socks5client.Socks5Client{Server: f.Setting.LocalAddress, Port: f.Setting.LocalPort, Address: addr}
				return x.NewSocks5Client()
			}
			dnsFuncParent = func(domain string) (DNS []string, success bool) {
				return dns.DNSOverHTTPS(f.Setting.DnsServer, domain, proxy)
			}
		} else {
			dnsFuncParent = func(domain string) (DNS []string, success bool) {
				return dns.DNSOverHTTPS(f.Setting.DnsServer, domain, nil)
			}
		}
	case false:
		dnsFuncParent = func(domain string) (DNS []string, success bool) {
			return dns.DNS(f.Setting.DnsServer, domain)
		}
	}
	return func(domain string) (DNS []string, success bool) {
		var dnsS []string
		var isSuccess bool
		if dnsS, isSuccess = f.dnsCache.Get(domain); !isSuccess {
			dnsS, isSuccess = dnsFuncParent(domain)
			f.dnsCache.Add(domain, dnsS)
			return dnsS, isSuccess
		}
		return dnsS, isSuccess
	}
}

func (f *ForwardFunc) log(v ...interface{}) {
	if f.Log != nil {
		f.Log(v)
	} else {
		log.Println(v...)
	}
}

func (f *ForwardFunc) Forward(host string) (conn net.Conn, err error) {
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

	switch f.Matcher {
	default:
		hosts, proxy := f.Matcher.MatchStr(URI.Hostname())
		if proxy == "block" {
			return nil, errors.New("block domain: " + host)
		} else if proxy == "direct" {
			proxyURI, err = url.Parse("direct://0.0.0.0:0")
			if err != nil {
				return nil, err
			}
		} else if proxy == "proxy" {
			proxyURI, err = url.Parse("socks5://" + f.Setting.LocalAddress + ":" + f.Setting.LocalPort)
			if err != nil {
				return nil, err
			}
			if f.Setting.IsPrintLog {
				f.log("Mode: " + mode + " | Domain: " + host + " | match to " + proxy)
			}
			return getproxyconn.ForwardTo(host, *proxyURI)
		} else {
			proxy = "default"
			proxyURI, err = url.Parse("socks5://" + f.Setting.LocalAddress + ":" + f.Setting.LocalPort)
			if err != nil {
				return nil, err
			}
		}
		if f.Setting.UseLocalDNS {
			for x := range hosts {
				host = net.JoinHostPort(hosts[x], URI.Port())
				conn, err = getproxyconn.ForwardTo(host, *proxyURI)
				if err == nil {
					if f.Setting.IsPrintLog {
						f.log("Mode: " + mode + " | Domain: " + host + " | match to " + proxy)
					}
					return conn, nil
				}
			}
		} else {
			if f.Setting.IsPrintLog {
				f.log("Mode: " + mode + " | Domain: " + host + " | match to " + proxy)
			}
			return getproxyconn.ForwardTo(host, *proxyURI)
		}
		return nil, errors.New("make connection:" + net.JoinHostPort(hosts[len(hosts)-1], URI.Port()) + " with proxy:" + proxy + " error")
	case nil:
		proxy = "Direct"
		proxyURI, err = url.Parse("direct://0.0.0.0:0")
		if err != nil {
			return nil, err
		}
	}
	if f.Setting.IsPrintLog {
		f.log("Mode: " + mode + " | Domain: " + host + " | match to " + proxy)
	}
	conn, err = getproxyconn.ForwardTo(host, *proxyURI)
	return
}
