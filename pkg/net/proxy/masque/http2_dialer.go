package masque

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/masque/connectip"
)

// connectHTTP2 establishes Cloudflare CONNECT-IP via TLS and extended HTTP/2 CONNECT.
func (m *Masque) connectHTTP2(ctx context.Context) (*Conn, error) {
	c := &Conn{}
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
	request, err := connectip.NewRequest(ctx, ConnectURI+"/")
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	request.Header()["User-Agent"] = []string{""}
	ipConn, resp, err := connectip.NewCloudflareHTTP2ClientConn(h2).Dial(request)
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
