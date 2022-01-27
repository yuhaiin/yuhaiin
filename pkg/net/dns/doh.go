package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

var _ DNS = (*doh)(nil)

type doh struct {
	DNS
	*utils.ClientUtil

	Subnet *net.IPNet
	Proxy  func(domain string) (net.Conn, error)

	host     string
	hostname string
	port     string
	url      string

	cache      *utils.LRU
	httpClient *http.Client
}

func NewDoH(host string, subnet *net.IPNet, p proxy.Proxy) DNS {
	dns := &doh{
		Subnet: subnet,
		cache:  utils.NewLru(200, 20*time.Minute),
	}

	dns.setServer(host)

	if p == nil {
		dns.setProxy(func(s string) (net.Conn, error) {
			return dns.ClientUtil.GetConn()
		})
	} else {
		dns.setProxy(p.Conn)
	}

	return dns
}

// LookupIP .
// https://tools.ietf.org/html/rfc8484
func (d *doh) LookupIP(domain string) (ip []net.IP, err error) {
	if x, _ := d.cache.Load(domain); x != nil {
		return x.([]net.IP), nil
	}
	if ip, err = d.search(domain); len(ip) != 0 {
		d.cache.Add(domain, ip)
	}
	return
}

func (d *doh) search(domain string) ([]net.IP, error) {
	DNS, err := reqAndHandle(domain, d.Subnet, d.post)
	if err != nil || len(DNS) == 0 {
		return nil, fmt.Errorf("doh resolve domain %s failed: %v", domain, err)
	}
	return DNS, nil
}

func (d *doh) setServer(host string) {
	d.url = "https://" + host
	uri, err := url.Parse("//" + host)
	if err != nil {
		d.hostname = host
		d.port = "443"
	} else {
		d.hostname = uri.Hostname()
		d.port = uri.Port()
		if d.port == "" {
			d.port = "443"
		}
		if uri.Path == "" {
			d.url += "/dns-query"
		}
	}

	if net.ParseIP(d.hostname) == nil {
		ip, err := net.LookupIP(d.hostname)
		if err != nil {
			ip = append(ip, net.ParseIP("1.1.1.1"))
		}
		d.hostname = ip[0].String()
	}

	d.host = net.JoinHostPort(d.hostname, d.port)
	d.ClientUtil = utils.NewClientUtil(d.hostname, d.port)
}

func (d *doh) setProxy(p func(string) (net.Conn, error)) {
	d.Proxy = p
	d.httpClient = &http.Client{
		Transport: &http.Transport{
			//Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				switch network {
				case "tcp":
					return d.Proxy(d.host)
				default:
					return net.Dial(network, d.host)
				}
			},
			TLSClientConfig:   new(tls.Config),
			DisableKeepAlives: false,
		},
		Timeout: 10 * time.Second,
	}
}

func (d *doh) get(dReq []byte) (body []byte, err error) {
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
func (d *doh) post(dReq []byte) (body []byte, err error) {
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

func (d *doh) Resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return dohDial(d.url, d.httpClient), nil
		},
	}
}

var _ net.Conn = (*dohResolverDial)(nil)
var _ net.PacketConn = (*dohResolverDial)(nil)

type dohResolverDial struct {
	host       string
	deadline   time.Time
	buffer     *bytes.Buffer
	httpClient *http.Client
}

func dohDial(host string, client *http.Client) net.Conn {
	return &dohResolverDial{
		host:       host,
		buffer:     bytes.NewBuffer(nil),
		httpClient: client,
	}
}

func (d *dohResolverDial) Write(data []byte) (int, error) {
	return d.WriteTo(data, nil)
}

func (d *dohResolverDial) Read(data []byte) (int, error) {
	n, err := d.buffer.Read(data)
	return n, err
}

func (d *dohResolverDial) WriteTo(data []byte, _ net.Addr) (int, error) {
	if time.Now().After(d.deadline) {
		return 0, fmt.Errorf("write deadline")
	}
	resp, err := d.httpClient.Post(d.host, "application/dns-message", bytes.NewReader(data))
	if err != nil {
		return 0, fmt.Errorf("post failed: %v", err)
	}
	defer resp.Body.Close()
	_, err = d.buffer.ReadFrom(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("read from body failed: %v", err)
	}
	return len(data), nil
}

func (d *dohResolverDial) ReadFrom(data []byte) (n int, addr net.Addr, err error) {
	if time.Now().After(d.deadline) {
		return 0, nil, fmt.Errorf("read deadline")
	}

	n, err = d.buffer.Read(data)
	return n, nil, err
}

func (d *dohResolverDial) Close() error {
	return nil
}

func (d *dohResolverDial) SetDeadline(t time.Time) error {
	d.deadline = t
	return nil
}

func (d *dohResolverDial) SetReadDeadline(t time.Time) error {
	return nil
}

func (d *dohResolverDial) SetWriteDeadline(t time.Time) error {
	return nil
}

func (d *dohResolverDial) LocalAddr() net.Addr {
	return nil
}
func (d *dohResolverDial) RemoteAddr() net.Addr {
	return nil
}
