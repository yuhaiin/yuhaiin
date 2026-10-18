package masque

import (
    "context"
    "crypto/tls"
    "fmt"
    "net"
    "time"
    "github.com/Asutorufa/yuhaiin/pkg/net/proxy/masque/connectip"
)

// connectHTTP2 establishes Cloudflare CONNECT-IP via TLS and extended HTTP/2 CONNECT.
func (m *Masque) connectHTTP2(ctx context.Context) (*Conn, error) {
    c := &Conn{}
    tcp, err := (&net.Dialer{}).DialContext(ctx, "tcp", m.addr.String())
    if err != nil { return nil, err }
    cfg := m.TlsConfig.Clone()
    cfg.NextProtos = []string{"h2"}
    secure := tls.Client(tcp, cfg)
    if err := secure.HandshakeContext(ctx); err != nil { _ = secure.Close(); return nil, fmt.Errorf("MASQUE HTTP/2 handshake: %w",err) }
    if secure.ConnectionState().NegotiatedProtocol != "h2" && secure.ConnectionState().NegotiatedProtocol != "" {
       _ = secure.Close()
       return nil, fmt.Errorf("MASQUE HTTP/2 requires ALPN h2, got %q", secure.ConnectionState().NegotiatedProtocol)
    }
    h2, err := newHTTP2ClientConn(secure, 30*time.Second)
    if err != nil { _ = secure.Close(); return nil, err }
    c.h2 = h2
    request, err := connectip.NewRequest(ctx, ConnectURI+"/")
    if err != nil { _ = c.Close(); return nil, err }
    ipConn, resp, err := connectip.NewCloudflareHTTP2ClientConn(h2).Dial(request)
    if err != nil { _ = c.Close(); return nil, fmt.Errorf("MASQUE HTTP/2 CONNECT-IP: %w",err) }
    return finishMasqueConnect(c, ipConn, resp)
}
