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
)

type DOH struct {
	Server string
	Subnet *net.IPNet
	Proxy  func(domain string) (net.Conn, error)
}

func NewDOH(host string) DNS {
	_, subnet, _ := net.ParseCIDR("0.0.0.0/0")
	return &DOH{
		Server: host,
		Subnet: subnet,
		Proxy: func(domain string) (net.Conn, error) {
			return net.DialTimeout("tcp", domain, 5*time.Second)
		},
	}
}

// DOH DNS over HTTPS
// https://tools.ietf.org/html/rfc8484
func (d *DOH) Search(domain string) (DNS []net.IP, err error) {
	return dnsCommon(domain, d.Subnet, func(data []byte) ([]byte, error) { return d.post(data, d.Server) })
}

func (d *DOH) SetSubnet(ip *net.IPNet) {
	if ip == nil {
		_, d.Subnet, _ = net.ParseCIDR("0.0.0.0/0")
		return
	}
	d.Subnet = ip
}

func (d *DOH) GetSubnet() *net.IPNet {
	return d.Subnet
}

func (d *DOH) SetServer(host string) {
	d.Server = host
}

func (d *DOH) SetProxy(proxy func(addr string) (net.Conn, error)) {
	d.Proxy = proxy
}

func (d *DOH) get(dReq []byte, server string) (body []byte, err error) {
	query := strings.Replace(base64.URLEncoding.EncodeToString(dReq), "=", "", -1)
	urls := "https://" + server + "/dns-query?dns=" + query
	res, err := http.Get(urls)
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
func (d *DOH) post(dReq []byte, server string) (body []byte, err error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.Proxy(addr)
		}}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader(dReq))
	if err != nil {
		return nil, fmt.Errorf("DOH:post() newReq -> %v", err)
	}
	urls, err := url.Parse("//" + server)
	if err != nil {
		return nil, fmt.Errorf("DOH:post() urlParse -> %v", err)
	}
	req.URL.Scheme = "https"
	req.URL.Host = urls.Host
	req.URL.Path = urls.Path + "/dns-query"
	req.Header.Set("accept", "application/dns-message")
	req.Header.Set("content-type", "application/dns-message")
	req.ContentLength = int64(len(dReq))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DOH:post() req -> %v", err)
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("DOH:post() readBody -> %v", err)
	}
	return
}
