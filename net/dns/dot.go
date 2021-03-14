package dns

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"
)

type DoT struct {
	DNS
	host         string
	servername   string
	subnet       *net.IPNet
	proxy        func(string) (net.Conn, error)
	sessionCache tls.ClientSessionCache
}

func NewDoT(host string, subnet *net.IPNet) *DoT {
	if subnet == nil {
		_, subnet, _ = net.ParseCIDR("0.0.0.0/0")
	}
	servername, _, _ := net.SplitHostPort(host)
	return &DoT{
		host:         host,
		subnet:       subnet,
		servername:   servername,
		sessionCache: tls.NewLRUClientSessionCache(0),
		proxy: func(s string) (net.Conn, error) {
			return net.DialTimeout("tcp", s, time.Second*5)
		},
	}
}

func (d *DoT) SetProxy(f func(string) (net.Conn, error)) {
	if f == nil {
		d.proxy = func(s string) (net.Conn, error) {
			return net.DialTimeout("tcp", s, time.Second*5)
		}
	}
	d.proxy = f
}

func (d *DoT) SetServer(host string) {
	if host == "" {
		log.Println("set dot host is empty, skip")
		return
	}
	d.host = host
	servername, _, _ := net.SplitHostPort(host)
	d.servername = servername
}

func (d *DoT) SetSubnet(subnet *net.IPNet) {
	d.subnet = subnet
}

func (d *DoT) Search(domain string) ([]net.IP, error) {
	conn, err := d.proxy(d.host)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %v", err)
	}
	conn = tls.Client(conn, &tls.Config{
		ServerName:         d.servername,
		ClientSessionCache: d.sessionCache,
	})
	defer conn.Close()
	return dnsCommon(domain, d.subnet, func(reqData []byte) (body []byte, err error) {
		length := len(reqData) // dns over tcp, prefix two bytes is request data's length
		reqData = append([]byte{byte(length >> 8), byte(length - ((length >> 8) << 8))}, reqData...)
		_, err = conn.Write(reqData)
		if err != nil {
			return nil, fmt.Errorf("write data failed: %v", err)
		}

		leg := make([]byte, 2)
		_, err = conn.Read(leg)
		if err != nil {
			return nil, fmt.Errorf("read data length from server failed %v", err)
		}
		all := make([]byte, int(leg[0])<<8+int(leg[1]))
		_, err = conn.Read(all)
		if err != nil {
			return nil, fmt.Errorf("read data from server failed: %v", err)
		}
		return all, err
	})
}
