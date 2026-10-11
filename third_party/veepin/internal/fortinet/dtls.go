package fortinet

// The DTLS data channel.
//
// FortiOS offers a UDP alternative to the TLS tunnel: the same framed PPP, but
// each record in its own datagram, so a tunnelled TCP flow is not stacked on top
// of the gateway's TCP. The config XML advertises it with dtls="1" and the
// client, having logged in over HTTPS, brings up a DTLS session to the same port
// number on UDP.
//
// DTLS here is certificate-based (ECDHE-ECDSA), unlike AnyConnect's PSK channel:
// there is no exporter binding it to the HTTPS session, so the session proves
// only who the *server* is. The client is authorised separately, by presenting
// its SVPNCOOKIE in the GFtype exchange (see gftype.go) as the first application
// datagrams. Only a cookie the HTTPS login issued gets a PPP link.

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/xen0bit/veepin/internal/dtls"
	"github.com/xen0bit/veepin/internal/udpmux"
)

const (
	// dtlsHandshakeTimeout bounds the DTLS handshake itself.
	dtlsHandshakeTimeout = 10 * time.Second
	// gfHandshakeTimeout bounds the GFtype exchange after it. A client that
	// completes a handshake and then says nothing costs a goroutine and a peer
	// slot, so it is not allowed to hold either for long.
	gfHandshakeTimeout = 10 * time.Second
	// maxDTLSDatagram bounds a received datagram: one framed PPP record plus the
	// DTLS record overhead, rounded up.
	maxDTLSDatagram = 2048
	// dtlsMTU bounds DTLS records on the wire. It leaves room under a 1500-octet
	// path for the IP and UDP headers and the DTLS record overhead, so a full
	// inner packet still fits one datagram and is never fragmented.
	dtlsMTU = 1400
)

// ErrNoDTLS reports that the server was built without a certificate for the
// UDP channel, so ServeDTLS has nothing to offer.
var ErrNoDTLS = errors.New("fortinet: no certificate configured for the DTLS channel")

// EnableDTLS binds the UDP data channel to conn and returns the loop that serves
// it. Enabling and serving are separate so the channel is advertised in the
// config XML the moment it exists, with no window in which a client is told to
// use a socket that is not yet being read.
func (s *Server) EnableDTLS(conn *net.UDPConn) (serve func(), err error) {
	if s.cfg.Certificate == nil {
		return nil, ErrNoDTLS
	}
	mux := udpmux.New(conn, maxDTLSDatagram, s.admitDTLS)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, net.ErrClosed
	}
	s.dtls = mux
	s.log.Printf("fortinet: DTLS data channel listening on %s", conn.LocalAddr())
	return mux.Serve, nil
}

// admitDTLS decides whether a datagram from an unknown peer starts a session.
// Only a ClientHello does; the cookie that authorises the flow comes later,
// inside the established session, so nothing here can be trusted beyond "this
// looks like the start of a handshake".
func (s *Server) admitDTLS(addr *net.UDPAddr, pkt []byte) func(*udpmux.Conn) {
	if !dtls.IsClientHello(pkt) {
		// Logged because the alternative is a silent drop: when a client reports
		// that its DTLS channel failed, this is the line that says whether the
		// gateway ever saw the attempt.
		s.log.Printf("fortinet: ignoring a %d-octet datagram from %s that is not a ClientHello", len(pkt), addr)
		return nil
	}
	return s.serveDTLSPeer
}

func (s *Server) serveDTLSPeer(p *udpmux.Conn) {
	s.mu.Lock()
	mux, cert := s.dtls, s.cfg.Certificate
	s.mu.Unlock()

	conn, err := dtls.Server(p, dtls.Config{
		Certificate:      cert,
		MTU:              dtlsMTU,
		HandshakeTimeout: dtlsHandshakeTimeout,
	})
	if err != nil {
		s.log.Warnf("fortinet: DTLS handshake with %s failed: %v", p.RemoteAddr(), err)
		mux.Drop(p)
		return
	}

	if err := s.dtlsAuthorize(conn); err != nil {
		s.log.Warnf("fortinet: DTLS session from %s rejected: %v", p.RemoteAddr(), err)
		_ = conn.Close()
		mux.Drop(p)
	}
}

// dtlsAuthorize runs the GFtype exchange and puts the session to work. The
// cookie decides which of two things happens, and a cookie the login never
// issued gets neither:
//
//   - it names an active tunnel: a real client brings DTLS up *alongside* its
//     TLS tunnel and then prefers it, so this attaches to that link as a second
//     carrier and the PPP session continues untouched.
//   - it is still pending: the client went straight to UDP, so this session is
//     the tunnel, and a PPP server runs on it as it would over TLS.
//
// On success the session belongs to the link; on error the caller closes it.
func (s *Server) dtlsAuthorize(conn *dtls.Conn) error {
	_ = conn.SetReadDeadline(time.Now().Add(gfHandshakeTimeout))
	buf := make([]byte, maxDTLSDatagram)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("reading clthello: %w", err)
	}
	_ = conn.SetReadDeadline(time.Time{})

	cookie, err := ParseDTLSClientHello(buf[:n])
	if err != nil {
		return err
	}

	s.mu.Lock()
	link := s.byCookie[cookie]
	addr, pending := s.pending[cookie]
	if link == nil && pending {
		delete(s.pending, cookie)
	}
	s.mu.Unlock()

	if link == nil && !pending {
		return errors.New("unknown or already-used SVPNCOOKIE")
	}
	if _, err := conn.Write(BuildDTLSServerHello()); err != nil {
		if link == nil {
			s.gate.Done()
			s.cfg.Pool.Release(addr)
		}
		return fmt.Errorf("writing svrhello: %w", err)
	}

	if link != nil {
		link.attachDTLS(conn)
		s.log.Printf("fortinet: DTLS carrier attached to the tunnel for %s", link.assignedSrc)
		return nil
	}
	// The session's cost is now the link, not the admission gate — the same
	// accounting the TLS tunnel does when it takes over from a pending login.
	s.gate.Done()
	s.runServerLink(conn, nil, addr, true, cookie)
	return nil
}

// DialDTLS brings up the client side of the data channel: a certificate-based
// DTLS session to addr, then the GFtype exchange that presents the cookie the
// HTTPS login issued. The returned connection carries framed PPP, one record per
// datagram, and is what RunClient is handed for a DTLS tunnel.
func DialDTLS(conn net.Conn, cookie string, cfg *tls.Config) (*dtls.Conn, error) {
	dc, err := dtls.Client(conn, dtls.Config{
		MTU:                dtlsMTU,
		HandshakeTimeout:   dtlsHandshakeTimeout,
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		RootCAs:            cfg.RootCAs,
		// The gateway's certificate is checked against the same policy the HTTPS
		// login used, so DTLS is not a weaker second door into the same server.
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

// gfExchange presents the cookie and waits for the server's confirmation.
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
