package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	_ "unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2"
)

var (
	capsuleProtocolHeaderValue string = "?1"
	headers                           = http.Header{
		http3.CapsuleProtocolHeader: []string{capsuleProtocolHeaderValue},
		"User-Agent":                []string{""},
	}
)

// !! DialHttp2 WIP
func DialHttp2(ctx context.Context, dial func(ctx context.Context) (net.Conn, error), uri string, requestProtocol string, tlsConfig *tls.Config) (*connectip.Conn, *http.Response, error) {
	tlsConfig = tlsConfig.Clone()
	tlsConfig.NextProtos = []string{"h2"}

	transport := &http2.Transport{
		DisableCompression: true,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			conn, err := dial(ctx)
			if err != nil {
				return nil, err
			}

			return tls.Client(conn, tlsConfig), nil
		},
	}

	r, w := io.Pipe()

	req, err := http.NewRequest(http.MethodConnect, uri, io.NopCloser(r))
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to create request: %w", err)
	}

	req.Header = headers
	req.Proto = requestProtocol

	log.Info("start RoundTrip")
	rsp, err := transport.RoundTrip(req)
	log.Info("end RoundTrip")
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to read response: %w", err)
	}

	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		// _ = rsp.Body.Close()
		data, _ := io.ReadAll(rsp.Body)
		return nil, rsp, fmt.Errorf("connect-ip: server responded with %d, body: %s", rsp.StatusCode, data)
	}

	slog.Info("resp", "r", rsp)

	return newProxiedConn(&http2Stream{rsp.Body, w}), rsp, nil
}

// Dial dials a proxied connection to a target server.
func Dial(ctx context.Context, conn *http3.ClientConn, uri string, requestProtocol string) (*connectip.Conn, *http.Response, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to parse URI: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, nil, context.Cause(ctx)
	case <-conn.Context().Done():
		return nil, nil, context.Cause(conn.Context())
	case <-conn.ReceivedSettings():
	}
	settings := conn.Settings()
	if !settings.EnableDatagrams {
		return nil, nil, errors.New("connect-ip: server didn't enable datagrams")
	}

	rstr, err := conn.OpenRequestStream(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to open request stream: %w", err)
	}
	if err := rstr.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  requestProtocol,
		Host:   u.Host,
		Header: headers,
		URL:    u,
	}); err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to send request: %w", err)
	}
	// TODO: optimistically return the connection
	rsp, err := rstr.ReadResponse()
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to read response: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		return nil, rsp, fmt.Errorf("connect-ip: server responded with %d", rsp.StatusCode)
	}

	return newProxiedConn(rstr), rsp, nil
}

type http2Stream struct {
	io.ReadCloser
	io.Writer
}

func (h *http2Stream) ReceiveDatagram(context.Context) ([]byte, error) {
	select {}
}

func (h *http2Stream) SendDatagram(b []byte) error {
	log.Info("write http2 datagram", "len", len(b))
	w := quicvarint.NewWriter(h.Writer)
	return http3.WriteCapsule(w, 0, b)
}

func (h *http2Stream) CancelRead(quic.StreamErrorCode) {}

type http3Stream interface {
	io.ReadWriteCloser
	ReceiveDatagram(context.Context) ([]byte, error)
	SendDatagram([]byte) error
	CancelRead(quic.StreamErrorCode)
}

//go:linkname newProxiedConn github.com/quic-go/connect-ip-go.newProxiedConn
func newProxiedConn(str http3Stream) *connectip.Conn
