package getproxyconn

import (
	"SsrMicroClient/net/proxy/socks5/client"
	"net"
	"net/url"
	"time"
)

func ForwardTo(host string, proxy url.URL) (net.Conn, error) {
	switch proxy.Scheme {
	case "direct":
		return toTCP(host)
	case "socks5":
		return toSocks5(host, proxy.Hostname(), proxy.Port())
	case "https", "http":
		return toHTTP(host, proxy.Host)
	default:
		return toTCP(host)
	}
}

func toSocks5(host string, s5Server, s5Port string) (socks5Conn net.Conn, err error) {
	return (&socks5client.Client{Server: s5Server, Port: s5Port, Address: host}).NewSocks5Client()
}

func toTCP(host string) (net.Conn, error) {
	return net.DialTimeout("tcp", host, 10*time.Second)
}

func toHTTP(host string, httpProxyServer string) (server net.Conn, err error) {
	server, err = net.Dial("tcp", httpProxyServer)
	if err != nil {
		return
	}
	if _, err = server.Write([]byte("CONNECT " + host + " HTTP/1.1\r\n\r\n")); err != nil {
		return
	}
	httpConnect := make([]byte, 1024)
	if _, err = server.Read(httpConnect[:]); err != nil {
		return
	}
	return server, nil
}
