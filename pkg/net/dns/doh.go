package dns

import (
	"bytes"
	"context"
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
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

func init() {
	Register(config.Dns_doh, func(c dns.Config, p proxy.Proxy) dns.DNS { return NewDoH(c, p) })
}

var _ dns.DNS = (*doh)(nil)

type doh struct{ *client }

func NewDoH(config dns.Config, p proxy.StreamProxy) dns.DNS {
	url, addr, err := getUrlAndHost(config.Host, config.Servername)
	if err != nil {
		return dns.NewErrorDNS(err)
	}

	if p == nil {
		p = simple.NewSimple(addr, nil)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				switch network {
				case "tcp":
					return p.Conn(addr)
				default:
					return nil, fmt.Errorf("unsupported network: %s", network)
				}
			},
		},
		Timeout: 30 * time.Second,
	}

	return &doh{
		client: NewClient(config, func(b []byte) ([]byte, error) {
			req, err := http.NewRequest("POST", url, bytes.NewBuffer(b))
			if err != nil {
				return nil, fmt.Errorf("doh new request failed: %v", err)
			}
			req.Header.Set("Content-Type", "application/dns-message")
			req.Header.Set("Accept", "application/dns-message")
			req.Header.Set("User-Agent", string([]byte{' '}))
			resp, err := httpClient.Do(req)
			if err != nil {
				return nil, fmt.Errorf("doh post failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				utils.Copy(io.Discard, resp.Body) // from v2fly
				return nil, fmt.Errorf("doh post return code: %d", resp.StatusCode)
			}
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
		}),
	}
}

func (d *doh) Close() error { return nil }

// https://tools.ietf.org/html/rfc8484
func getUrlAndHost(host, servername string) (_ string, addr proxy.Address, _ error) {
	var urls string
	if !strings.HasPrefix(host, "https://") {
		urls = "https://" + host
	} else {
		urls = host
	}

	uri, err := url.Parse(urls)
	if err != nil {
		return "", nil, fmt.Errorf("doh parse url failed: %v", err)
	}

	hostname, port := uri.Hostname(), uri.Port()
	if port == "" {
		port = "443"
	}
	if uri.Path == "" {
		uri.Path = "/dns-query"
	}
	if servername != "" {
		uri.Host = net.JoinHostPort(servername, port)
	}

	por, _ := strconv.ParseUint(port, 10, 16)
	return uri.String(), proxy.ParseAddressSplit("tcp", hostname, uint16(por)), nil
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
