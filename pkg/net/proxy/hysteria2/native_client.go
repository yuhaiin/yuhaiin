package hysteria2

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/hysteria2/internal/congestion"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/hysteria2/internal/wire"
)

type nativeClientSession struct {
	conn      *quic.Conn
	transport *quic.Transport
	http      *http3.Transport
	socket    net.PacketConn
	local     net.Addr
	udp       *nativeUDPManager
	closeOnce sync.Once
}

func dialNativeSession(ctx context.Context, factory *connFactory, server net.Addr, password string, tlsConfig *tls.Config, upload, download uint64) (_ *nativeClientSession, err error) {
	socket, err := factory.New(server)
	if err != nil {
		return nil, err
	}
	tr := &quic.Transport{Conn: socket, ConnectionIDGenerator: quic.ZeroLengthConnectionIDGenerator{}}
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     8 << 20,
		MaxStreamReceiveWindow:         8 << 20,
		InitialConnectionReceiveWindow: 20 << 20,
		MaxConnectionReceiveWindow:     20 << 20,
		MaxIdleTimeout:                 30 * time.Second,
		KeepAlivePeriod:                10 * time.Second,
		EnableDatagrams:                true,
		MaxDatagramFrameSize:           wire.MaxDatagram,
		OmitMaxDatagramFrameSize:       true,
		DisablePathManager:             true,
		ChromeParrot:                   true,
	}
	var conn *quic.Conn
	rt := &http3.Transport{
		TLSClientConfig: tlsConfig, QUICConfig: quicConfig,
		Dial: func(ctx context.Context, _ string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			c, err := tr.DialEarly(ctx, server, tc, qc)
			if err == nil {
				conn = c
			}
			return c, err
		},
	}
	defer func() {
		if err != nil {
			_ = rt.Close()
			if conn != nil {
				_ = conn.CloseWithError(0x101, "")
			}
			_ = tr.Close()
			_ = socket.Close()
		}
	}()
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Scheme: "https", Host: wire.AuthHost, Path: wire.AuthPath},
		Header: make(http.Header),
	}
	if err = wire.WriteClientAuth(req.Header, wire.ClientAuth{Password: password, ReceiveBytesPerSecond: download}); err != nil {
		return nil, err
	}
	var resp *http.Response
	resp, err = rt.RoundTrip(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("hysteria2 authentication request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wire.AuthOK || conn == nil {
		return nil, fmt.Errorf("hysteria2 authentication failed (HTTP %d)", resp.StatusCode)
	}
	answer := wire.ReadServerAuth(resp.Header)
	actualTx := answer.ReceiveBytesPerSecond
	if actualTx == 0 || actualTx > upload {
		actualTx = upload
	}
	if answer.AutoBandwidth || actualTx == 0 {
		congestion.UseConfigured(conn, "", "")
	} else {
		congestion.UseBrutal(conn, actualTx, false)
	}
	s := &nativeClientSession{conn: conn, transport: tr, http: rt, socket: socket, local: factory.local}
	if answer.UDPEnabled {
		s.udp = newNativeUDPManager(conn)
	}
	return s, nil
}

func (s *nativeClientSession) Context() context.Context { return s.conn.Context() }

func (s *nativeClientSession) TCPContext(ctx context.Context, destination string) (net.Conn, error) {
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	abort := context.AfterFunc(ctx, func() { stream.CancelRead(0); stream.CancelWrite(0) })
	defer abort()
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}
	defer func() { _ = stream.SetDeadline(time.Time{}) }()
	if err := wire.WriteTCPRequest(stream, destination); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}
	ok, message, err := wire.ReadTCPResponse(stream)
	if err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}
	if !ok {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, fmt.Errorf("hysteria2 connect rejected: %s", message)
	}
	return &nativeTCPConn{Stream: stream, local: s.conn.LocalAddr(), remote: s.conn.RemoteAddr()}, nil
}

func (s *nativeClientSession) UDP() (hyUDPConn, error) {
	if s.udp == nil {
		return nil, errors.New("hysteria2: UDP disabled by server")
	}
	return s.udp.newSession()
}

func (s *nativeClientSession) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		if s.conn != nil {
			closeErr = errors.Join(closeErr, s.conn.CloseWithError(0x100, ""))
		}
		if s.http != nil {
			closeErr = errors.Join(closeErr, s.http.Close())
		}
		if s.transport != nil {
			closeErr = errors.Join(closeErr, s.transport.Close())
		}
		if s.socket != nil {
			closeErr = errors.Join(closeErr, s.socket.Close())
		}
	})
	return closeErr
}

type nativeTCPConn struct {
	*quic.Stream
	local, remote net.Addr
}

func (s *nativeTCPConn) Close() error {
	_ = s.CloseRead()
	return s.CloseWrite()
}

// QUIC FIN and STOP_SENDING are independent. Relay must be able to finish
// sending a request without discarding a response still being received.
func (s *nativeTCPConn) CloseWrite() error { return s.Stream.Close() }
func (s *nativeTCPConn) CloseRead() error {
	s.Stream.CancelRead(0)
	return nil
}
func (s *nativeTCPConn) LocalAddr() net.Addr  { return s.local }
func (s *nativeTCPConn) RemoteAddr() net.Addr { return s.remote }

var _ net.Conn = (*nativeTCPConn)(nil)
