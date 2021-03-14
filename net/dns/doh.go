package dns

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/net/utils"
)

type DoH struct {
	DNS
	*utils.ClientUtil

	Subnet *net.IPNet
	Proxy  func(domain string) (net.Conn, error)

	host string
	port string
	url  string

	cache      *utils.LRU
	httpClient *http.Client
}

func NewDoH(host string, subnet *net.IPNet) DNS {
	if subnet == nil {
		_, subnet, _ = net.ParseCIDR("0.0.0.0/0")
	}
	dns := &DoH{
		Subnet: subnet,
		cache:  utils.NewLru(200, 20*time.Minute),
	}

	dns.SetServer(host)

	dns.SetProxy(func(domain string) (net.Conn, error) {
		return dns.ClientUtil.GetConn()
	})
	return dns
}

// Search
// https://tools.ietf.org/html/rfc8484
func (d *DoH) Search(domain string) (ip []net.IP, err error) {
	if x := d.cache.Load(domain); x != nil {
		return x.([]net.IP), nil
	}
	if ip, err = d.search(domain); len(ip) != 0 {
		d.cache.Add(domain, ip)
	}
	return
}

func (d *DoH) search(domain string) ([]net.IP, error) {
	DNS, err := dnsCommon(
		domain,
		d.Subnet,
		func(data []byte) ([]byte, error) {
			return d.post(data)
		},
	)
	if err != nil || len(DNS) == 0 {
		return nil, fmt.Errorf("doh resolve domain %s failed: %v", domain, err)
	}
	return DNS, nil
}

func (d *DoH) SetSubnet(ip *net.IPNet) {
	if ip == nil {
		_, d.Subnet, _ = net.ParseCIDR("0.0.0.0/0")
	} else {
		d.Subnet = ip
	}
}

func (d *DoH) GetSubnet() *net.IPNet {
	return d.Subnet
}

func (d *DoH) SetServer(host string) {
	uri, err := url.Parse("//" + host)
	if err != nil {
		d.host = host
		d.port = "443"
	} else {
		d.host = uri.Hostname()
		d.port = uri.Port()
		if d.port == "" {
			d.port = "443"
		}
	}
	d.url = "https://" + host
	if uri.Path == "" {
		d.url += "/dns-query"
	}

	d.ClientUtil = utils.NewClientUtil(d.host, d.port)
}

func (d *DoH) GetServer() string {
	return d.url
}

func (d *DoH) SetProxy(proxy func(addr string) (net.Conn, error)) {
	if proxy == nil {
		return
	}
	d.Proxy = proxy
	d.httpClient = &http.Client{
		Transport: &http.Transport{
			//Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				switch network {
				case "tcp":
					return d.Proxy(addr)
				default:
					return net.Dial(network, addr)
				}
			},
			DisableKeepAlives: false,
		},
		Timeout: 10 * time.Second,
	}
}

func (d *DoH) get(dReq []byte) (body []byte, err error) {
	query := strings.Replace(base64.URLEncoding.EncodeToString(dReq), "=", "", -1)
	urls := d.url + "?dns=" + query
	res, err := d.httpClient.Get(urls)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return
}

// https://www.cnblogs.com/mafeng/p/7068837.html
func (d *DoH) post(dReq []byte) (body []byte, err error) {
	resp, err := d.httpClient.Post(d.url, "application/dns-message", bytes.NewReader(dReq))
	if err != nil {
		return nil, fmt.Errorf("doh post failed: %v", err)
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("doh read body failed: %v", err)
	}
	return
}
