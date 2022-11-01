package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	pdns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
)

func init() {
	Register(pdns.Type_doh, NewDoH)
}

var _ dns.DNS = (*doh)(nil)

type doh struct{ *client }

func NewDoH(config Config) dns.DNS {
	uri := getUrlAndHost(config.Host)
	req, err := http.NewRequest(http.MethodPost, uri, nil)
	if err != nil {
		return dns.NewErrorDNS(err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	if config.Servername == "" {
		config.Servername = req.URL.Hostname()
	}

	tlsConfig := &tls.Config{
		ServerName: config.Servername,
	}

	var addr proxy.Address
	roundTripper := &http.Transport{
		TLSClientConfig:   tlsConfig,
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, host string) (net.Conn, error) {
			switch network {
			case "tcp", "tcp4", "tcp6":
				if addr == nil {
					var err error
					addr, err = proxy.ParseAddress(network, host)
					if err != nil {
						return nil, fmt.Errorf("doh parse address failed: %v", err)
					}
				}
				return config.Dialer.Conn(addr)
			default:
				return nil, fmt.Errorf("unsupported network: %s", network)
			}
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	hc := &http.Client{
		Transport: roundTripper,
		Timeout:   time.Second * 10,
	}
	return &doh{
		client: NewClient(config, func(b []byte) ([]byte, error) {
			req := req.Clone(context.Background())
			req.Body = io.NopCloser(bytes.NewBuffer(b))

			resp, err := hc.Do(req)
			if err != nil {
				return nil, fmt.Errorf("doh post failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				utils.Copy(io.Discard, resp.Body) // from v2fly
				return nil, fmt.Errorf("doh post return code: %d", resp.StatusCode)
			}

			return io.ReadAll(resp.Body)

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
func getUrlAndHost(host string) string {
	scheme, rest, _ := utils.GetScheme(host)
	if scheme == "" {
		host = "https://" + host
	}

	rest = strings.TrimPrefix(rest, "//")

	if rest == "" {
		host += "no-host-specified"
	}

	if !strings.Contains(rest, "/") {
		host = host + "/dns-query"
	}

	return host
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
