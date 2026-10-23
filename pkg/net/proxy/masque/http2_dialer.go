package masque

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/masque/connectip"
)

// connectHTTP2 establishes Cloudflare CONNECT-IP using ordinary HTTP/2 CONNECT
// with cf-connect-proto, not the RFC 8441 :protocol pseudo-header.
func (m *Masque) connectHTTP2(ctx context.Context) (*Conn, error) {
	c := &Conn{cloudflare: !m.generic}
	tcp, err := dialer.DialTCPContext(ctx, m.addr.AddrPort())
	if err != nil {
		return nil, err
	}
	// The HTTP/2 preface and initial SETTINGS are written before its reader
	// starts. A blocked socket must still honor the caller's setup deadline.
	stop := context.AfterFunc(ctx, func() { _ = tcp.Close() })
	defer stop()
	cfg := m.TlsConfig.Clone()
	cfg.NextProtos = []string{"h2"}
	secure := tls.Client(tcp, cfg)
	if err := secure.HandshakeContext(ctx); err != nil {
		_ = secure.Close()
		return nil, fmt.Errorf("MASQUE HTTP/2 handshake: %w", err)
	}
	if secure.ConnectionState().NegotiatedProtocol != "h2" && secure.ConnectionState().NegotiatedProtocol != "" {
		_ = secure.Close()
		return nil, fmt.Errorf("MASQUE HTTP/2 requires ALPN h2, got %q", secure.ConnectionState().NegotiatedProtocol)
	}
	h2, err := newHTTP2ClientConn(secure, 30*time.Second)
	if err != nil {
		_ = secure.Close()
		return nil, err
	}
	c.h2 = h2
	requestURL := m.requestURL
	if requestURL == "" {
		requestURL = ConnectURI + "/"
	}
	request, err := connectip.NewRequest(ctx, requestURL)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	var ipClient *connectip.HTTP2ClientConn
	if !m.generic {
		request.Header()["User-Agent"] = []string{""}
		ipClient = connectip.NewCloudflareHTTP2ClientConn(h2)
	} else {
		if m.bearerToken != "" {
			request.Header().Set("Authorization", "Bearer "+m.bearerToken)
		}
		ipClient = connectip.NewHTTP2ClientConn(h2)
	}
	ipConn, resp, err := ipClient.Dial(request)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("MASQUE HTTP/2 CONNECT-IP: %w", err)
	}
	if !stop() {
		_ = c.Close()
		return nil, context.Cause(ctx)
	}
	return finishMasqueConnect(c, ipConn, resp)
}
