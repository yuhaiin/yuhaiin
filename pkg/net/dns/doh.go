package dns

import (
	"bytes"
	"context"
	"crypto/tls"
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
	*client
	httpClient *http.Client
}

func NewDoH(config dns.Config, p proxy.StreamProxy) dns.DNS {
	dns := &doh{}

	url, addr := dns.getUrlAndHost(config.Host)

	if p == nil {
		p = simple.NewSimple(addr, nil)
	}

	dns.httpClient = &http.Client{
		Transport: &http.Transport{
			//Proxy: http.ProxyFromEnvironment,
			ForceAttemptHTTP2: true,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return p.Conn(addr)
			},
			TLSClientConfig: &tls.Config{ServerName: config.Servername},
		},
		Timeout: 4 * time.Second,
	}

	dns.client = NewClient(config, func(b []byte) ([]byte, error) {
		req, err := http.NewRequest("POST", url, bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("doh new request failed: %v", err)
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("User-Agent", string([]byte{' '}))
		resp, err := dns.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("doh post failed: %v", err)
		}
		defer resp.Body.Close()
		return ioutil.ReadAll(resp.Body)

		/*
			* Get
			urls := fmt.Sprintf(
				"%s?dns=%s",
				url,
				strings.TrimSuffix(base64.URLEncoding.EncodeToString(dReq), "="),
			)
			resp, err := httpClient.Get(urls)
		*/
	})
	return dns
}

func (d *doh) Close() error { return nil }

// https://tools.ietf.org/html/rfc8484
func (d *doh) getUrlAndHost(host string) (_ string, addr proxy.Address) {
	var urls string
	if !strings.HasPrefix(host, "https://") {
		urls = "https://" + host
	} else {
		urls = host
	}

	var hostname, port string
	uri, err := url.Parse(urls)
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
			urls += "/dns-query"
		}
	}

	por, _ := strconv.ParseUint(port, 10, 16)
	return urls, proxy.ParseAddressSplit("tcp", hostname, uint16(por))
}

func (d *doh) Resolver(f func(io.Reader) (io.ReadCloser, error)) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return dohConn(f), nil
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
