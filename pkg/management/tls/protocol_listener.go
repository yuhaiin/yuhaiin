package main

import (
	"bufio"
	"crypto/tls"
	"net"
	"sync"
	"time"
)

const protocolSniffTimeout = 10 * time.Second

// protocolListener serves cleartext HTTP and TLS connections from one socket.
// TLS clients begin with a handshake record (0x16, 0x03); all other input is
// passed to net/http as cleartext HTTP.
type protocolListener struct {
	listener  net.Listener
	tlsConfig *tls.Config
	accepted  chan acceptedConnection
	done      chan struct{}
	stopOnce  sync.Once
	stopErr   error
	pendingMu sync.Mutex
	pending   map[net.Conn]struct{}
}

type acceptedConnection struct {
	conn net.Conn
	raw  net.Conn
}

func newProtocolListener(listener net.Listener, tlsConfig *tls.Config) *protocolListener {
	result := &protocolListener{
		listener:  listener,
		tlsConfig: tlsConfig,
		accepted:  make(chan acceptedConnection, 32),
		done:      make(chan struct{}),
		pending:   make(map[net.Conn]struct{}),
	}
	go result.acceptLoop()
	return result
}

func (l *protocolListener) acceptLoop() {
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			l.stop(err)
			l.closePendingConnections()
			return
		}
		if !l.addPending(conn) {
			_ = conn.Close()
			return
		}
		go l.classify(conn)
	}
}

func (l *protocolListener) classify(conn net.Conn) {
	if err := conn.SetReadDeadline(time.Now().Add(protocolSniffTimeout)); err != nil {
		l.closePending(conn)
		return
	}
	reader := bufio.NewReader(conn)
	prefix, err := reader.Peek(3)
	if err != nil {
		l.closePending(conn)
		return
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		l.closePending(conn)
		return
	}

	classified := net.Conn(&bufferedConn{Conn: conn, reader: reader})
	if isTLSClientHello(prefix) {
		classified = tls.Server(classified, l.tlsConfig)
	}
	select {
	case l.accepted <- acceptedConnection{conn: classified, raw: conn}:
	case <-l.done:
		l.closePending(conn)
	}
}

func isTLSClientHello(prefix []byte) bool {
	return len(prefix) >= 3 && prefix[0] == 0x16 && prefix[1] == 0x03
}

func (l *protocolListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, l.stopErr
	default:
	}

	select {
	case accepted := <-l.accepted:
		if !l.finishAccept(accepted.raw) {
			_ = accepted.conn.Close()
			return nil, l.stopErr
		}
		return accepted.conn, nil
	case <-l.done:
		return nil, l.stopErr
	}
}

func (l *protocolListener) Close() error {
	l.stop(net.ErrClosed)
	err := l.listener.Close()
	l.closePendingConnections()
	return err
}

func (l *protocolListener) closePendingConnections() {
	l.pendingMu.Lock()
	for conn := range l.pending {
		_ = conn.Close()
		delete(l.pending, conn)
	}
	l.pendingMu.Unlock()
}

func (l *protocolListener) Addr() net.Addr {
	return l.listener.Addr()
}

func (l *protocolListener) stop(err error) {
	l.stopOnce.Do(func() {
		l.stopErr = err
		close(l.done)
	})
}

func (l *protocolListener) addPending(conn net.Conn) bool {
	l.pendingMu.Lock()
	defer l.pendingMu.Unlock()
	select {
	case <-l.done:
		return false
	default:
		l.pending[conn] = struct{}{}
		return true
	}
}

func (l *protocolListener) closePending(conn net.Conn) {
	l.pendingMu.Lock()
	delete(l.pending, conn)
	l.pendingMu.Unlock()
	_ = conn.Close()
}

func (l *protocolListener) finishAccept(conn net.Conn) bool {
	l.pendingMu.Lock()
	defer l.pendingMu.Unlock()
	select {
	case <-l.done:
		delete(l.pending, conn)
		return false
	default:
		delete(l.pending, conn)
		return true
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

var _ net.Listener = (*protocolListener)(nil)
var _ net.Conn = (*bufferedConn)(nil)
