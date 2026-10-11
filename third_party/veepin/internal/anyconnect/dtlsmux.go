package anyconnect

import (
	"net"
	"sync"

	"github.com/xen0bit/veepin/internal/dtls"
	"github.com/xen0bit/veepin/internal/udpmux"
)

// The server's DTLS listener.
//
// internal/udpmux does the demultiplexing — one socket, one Conn per peer
// address. What is specific to AnyConnect is the admission rule: a datagram from
// an unknown address starts a session only if it is a ClientHello whose
// session-id is an App-ID this server issued over HTTPS.
//
// The App-ID is unauthenticated at that point and is used purely as a lookup
// key. Forging one gets an attacker as far as a handshake they cannot complete,
// since the pre-shared key is derived from the TLS session and still has to
// match at Finished.

// dtlsListener admits DTLS sessions for App-IDs this server has handed out.
type dtlsListener struct {
	mux    *udpmux.Mux
	logger interface {
		Printf(string, ...any)
		Warnf(string, ...any)
	}

	mu      sync.Mutex
	pending map[string]*pendingSession
}

// pendingSession is an App-ID a server has issued but whose UDP flow has not
// arrived yet, together with the key that flow will be authenticated with.
type pendingSession struct {
	psk    []byte
	accept func(*dtls.Conn)
	mtu    int
}

func newDTLSListener(conn *net.UDPConn, logger interface {
	Printf(string, ...any)
	Warnf(string, ...any)
}) *dtlsListener {
	l := &dtlsListener{logger: logger, pending: map[string]*pendingSession{}}
	l.mux = udpmux.New(conn, maxPayload, l.admit)
	return l
}

// expect registers an App-ID this server has handed to a client, so the UDP flow
// that presents it can be matched to the session that authorised it.
func (l *dtlsListener) expect(appID string, s *pendingSession) {
	l.mu.Lock()
	l.pending[appID] = s
	l.mu.Unlock()
}

// forget drops an App-ID once its session ends.
func (l *dtlsListener) forget(appID string) {
	l.mu.Lock()
	delete(l.pending, appID)
	l.mu.Unlock()
}

// admit decides whether a datagram from a new peer begins a session. Anything
// that is not a ClientHello naming a known App-ID is ignored — an unknown peer
// cannot make the server allocate.
func (l *dtlsListener) admit(_ *net.UDPAddr, pkt []byte) func(*udpmux.Conn) {
	id, ok := dtls.ClientHelloSessionID(pkt)
	if !ok {
		return nil
	}
	l.mu.Lock()
	sess, expected := l.pending[string(id)]
	l.mu.Unlock()
	if !expected {
		return nil
	}
	return func(p *udpmux.Conn) { l.handshake(p, sess) }
}

// handshake completes the DTLS server handshake for a newly seen peer and hands
// the connection to the session that was waiting for it.
func (l *dtlsListener) handshake(p *udpmux.Conn, sess *pendingSession) {
	conn, err := dtls.Server(p, dtls.Config{
		PSK:              sess.psk,
		MTU:              sess.mtu,
		HandshakeTimeout: dtlsHandshakeTimeout,
	})
	if err != nil {
		l.logger.Warnf("anyconnect: DTLS handshake with %s failed: %v", p.RemoteAddr(), err)
		l.mux.Drop(p)
		return
	}
	sess.accept(conn)
}

func (l *dtlsListener) serve() { l.mux.Serve() }

func (l *dtlsListener) close() error { return l.mux.Close() }
