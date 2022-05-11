package dns

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

var _ dns.DNS = (*doh)(nil)

type doh struct {
	Proxy proxy.StreamProxy

	host proxy.Address
	url  string

	httpClient *http.Client
	*client
}

func NewDoH(host string, subnet *net.IPNet, p proxy.StreamProxy) dns.DNS {
	dns := &doh{}

	dns.setServer(host)
	if p == nil {
		p = simple.NewSimple(dns.host)
	}
	dns.setProxy(p)
	dns.client = NewClient(subnet, func(b []byte) ([]byte, error) {
		r, err := dns.post(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return ioutil.ReadAll(r)
	})
	return dns
}

func (d *doh) Close() error { return nil }

// https://tools.ietf.org/html/rfc8484

func (d *doh) setServer(host string) {
	if !strings.HasPrefix(host, "https://") {
		d.url = "https://" + host
	} else {
		d.url = host
	}

	var hostname, port string
	uri, err := url.Parse(d.url)
	if err != nil {
		hostname = host
		port = "443"
	} else {
		hostname = uri.Hostname()
		port = uri.Port()
		if port == "" {
			port = "443"
		}
		if uri.Path == "" {
			d.url += "/dns-query"
		}
	}

	por, _ := strconv.ParseUint(port, 10, 16)
	d.host = proxy.ParseAddressSplit("tcp", hostname, uint16(por))
}

func (d *doh) setProxy(p proxy.StreamProxy) {
	d.Proxy = p
	d.httpClient = &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: false,
			//Proxy: http.ProxyFromEnvironment,
			ForceAttemptHTTP2: true,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.Proxy.Conn(d.host)
			},
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
func (d *doh) post(req io.Reader) (io.ReadCloser, error) {
	resp, err := d.httpClient.Post(d.url, "application/dns-message", req)
	if err != nil {
		return nil, fmt.Errorf("doh post failed: %v", err)
	}

	return resp.Body, nil
}

func (d *doh) Resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return dohConn(d.post), nil
		},
	}
}

var _ net.Conn = (*dohUDPConn)(nil)
var _ net.PacketConn = (*dohUDPConn)(nil)

type dohUDPConn struct {
	hasDeadline bool
	deadline    time.Time

	buffer *bytes.Buffer
	handle func(io.Reader) (io.ReadCloser, error)
	body   io.ReadCloser
}

func dohConn(handle func(io.Reader) (io.ReadCloser, error)) net.Conn {
	return &dohUDPConn{
		buffer: utils.GetBuffer(),
		handle: handle,
	}
}

func (d *dohUDPConn) Write(data []byte) (int, error) {
	return d.WriteTo(data, nil)
}

func (d *dohUDPConn) Read(data []byte) (int, error) {
	n, _, err := d.ReadFrom(data)
	return n, err
}

func (d *dohUDPConn) WriteTo(data []byte, _ net.Addr) (int, error) {
	if d.hasDeadline && time.Now().After(d.deadline) {
		return 0, fmt.Errorf("write deadline")
	}

	d.buffer.Write(data)
	return len(data), nil
}

func (d *dohUDPConn) ReadFrom(data []byte) (n int, addr net.Addr, err error) {
	if d.hasDeadline && time.Now().After(d.deadline) {
		return 0, nil, fmt.Errorf("read deadline")
	}

	if d.body == nil {
		d.body, err = d.handle(d.buffer)
		if err != nil {
			return 0, nil, fmt.Errorf("doh read body failed: %v", err)
		}
	}

	n, err = d.body.Read(data)
	if err != nil && errors.Is(err, io.EOF) {
		err = nil
		d.body.Close()
		d.body = nil
	}
	return n, &net.IPAddr{IP: net.IPv4zero}, err
}

func (d *dohUDPConn) Close() error {
	if d.body != nil {
		return d.body.Close()
	}
	utils.PutBuffer(d.buffer)

	return nil
}

func (d *dohUDPConn) SetDeadline(t time.Time) error {
	if t.IsZero() {
		d.hasDeadline = false
	}
	d.deadline = t
	return nil
}

func (d *dohUDPConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (d *dohUDPConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (d *dohUDPConn) LocalAddr() net.Addr {
	return nil
}
func (d *dohUDPConn) RemoteAddr() net.Addr {
	return nil
}
