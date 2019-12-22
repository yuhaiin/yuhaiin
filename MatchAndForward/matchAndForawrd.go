package MatchAndForward

import (
	"SsrMicroClient/config/configjson"
	getproxyconn "SsrMicroClient/net/forward"
	"SsrMicroClient/net/matcher"
	"errors"
	"log"
	"net"
	"net/url"
)

type ForwardTo struct {
	Matcher *matcher.Match
	Config  *configjson.ConfigSample
	Setting *configjson.Setting
	Log     func(v ...interface{})
}

func NewForwardTo(configJsonPath, rulePath string) (forwardTo *ForwardTo, err error) {
	forwardTo = &ForwardTo{}
	forwardTo.Setting, err = configjson.SettingDecodeJSON(configJsonPath)
	if err != nil {
		return
	}
	forwardTo.Matcher, err = matcher.NewMatcherWithFile(forwardTo.Setting.DnsServer, rulePath)
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
		} else {
			proxy = "default"
			proxyURI, err = url.Parse("notFound://0.0.0.0:0")
			if err != nil {
				return nil, err
			}
		}
		for x := range hosts {
			host = net.JoinHostPort(hosts[x], URI.Port())
			conn, err = getproxyconn.ForwardTo(host, *proxyURI)
			if err == nil {
				ForwardTo.log("Mode: " + mode + " | Domain: " + host + " | match to " + proxy)
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
	ForwardTo.log("Mode: " + mode + " | Domain: " + host + " | match to " + proxy)
	conn, err = getproxyconn.ForwardTo(host, *proxyURI)
	return
}
