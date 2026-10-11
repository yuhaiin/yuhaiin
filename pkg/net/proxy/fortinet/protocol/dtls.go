package fortinet

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/dtls"
)

const (
	dtlsHandshakeTimeout = 10 * time.Second
	gfHandshakeTimeout   = 10 * time.Second
	maxDTLSDatagram      = 2048
	dtlsMTU              = 1400
)

// DialDTLS brings up the Fortinet client data channel and presents the cookie
// issued by the HTTPS login.
func DialDTLS(conn net.Conn, cookie string, cfg *tls.Config) (*dtls.Conn, error) {
	dc, err := dtls.Client(conn, dtls.Config{
		MTU:                dtlsMTU,
		HandshakeTimeout:   dtlsHandshakeTimeout,
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		RootCAs:            cfg.RootCAs,
	})
	if err != nil {
		return nil, fmt.Errorf("fortinet: DTLS handshake: %w", err)
	}
	if err := gfExchange(dc, cookie); err != nil {
		_ = dc.Close()
		return nil, err
	}
	return dc, nil
}

func gfExchange(dc *dtls.Conn, cookie string) error {
	if _, err := dc.Write(BuildDTLSClientHello(cookie)); err != nil {
		return fmt.Errorf("fortinet: sending clthello: %w", err)
	}
	_ = dc.SetReadDeadline(time.Now().Add(gfHandshakeTimeout))
	buf := make([]byte, maxDTLSDatagram)
	n, err := dc.Read(buf)
	if err != nil {
		return fmt.Errorf("fortinet: reading svrhello: %w", err)
	}
	_ = dc.SetReadDeadline(time.Time{})
	return ParseDTLSServerHello(buf[:n])
}
