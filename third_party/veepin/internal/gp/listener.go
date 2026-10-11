package gp

// Taking the packet tunnel off net/http.
//
// The tunnel endpoint is only nominally HTTP. The reference client opens it with
//
//	GET /ssl-tunnel-connect.sslvpn?user=…&authcookie=… HTTP/1.1\r\n\r\n
//
// — a bare request line and nothing else, no Host header — and expects the bytes
// "START_TUNNEL" back in place of a status line. A real gateway accepts that;
// Go's net/http does not, and rejects the request with 400 before any handler
// runs, because RFC 7230 §5.4 makes Host mandatory on HTTP/1.1.
//
// So the tunnel is split off in front of net/http rather than served by it. Every
// accepted connection has its request line read; the ones asking for the tunnel
// path are handed to the engine, and everything else is passed through with the
// bytes already read replayed, so the control plane is still ordinary net/http
// with cookies, routing and error handling for free.
//
// Doing it by request line rather than by "did this request have headers" means
// there is exactly one tunnel path in the server, whichever client opened it.

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// headLimit bounds the request head this reads before deciding. It is
	// generous for a request line and small enough that a peer sending an endless
	// header cannot make the gateway buffer without bound.
	headLimit = 8192
	// headTimeout bounds how long a connection may take to say what it wants.
	// Without it a peer that connects and stays silent holds a goroutine forever.
	headTimeout = 30 * time.Second
)

// Serve runs the gateway over ln until Close. ln must already terminate TLS.
// It blocks.
func (s *Server) Serve(ln net.Listener) error {
	hs := &http.Server{Handler: s}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = ln.Close()
		return net.ErrClosed
	}
	s.httpSrv = hs
	s.mu.Unlock()

	err := hs.Serve(s.split(ln))
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// split wraps ln so tunnel connections never reach net/http.
func (s *Server) split(ln net.Listener) net.Listener {
	sl := &splitListener{
		Listener: ln,
		srv:      s,
		accepted: make(chan net.Conn),
		done:     make(chan struct{}),
	}
	go sl.run()
	return sl
}

// splitListener accepts connections, classifies each one off the accept path,
// and hands net/http only the ones that are not the tunnel.
type splitListener struct {
	net.Listener
	srv *Server

	accepted chan net.Conn
	done     chan struct{}

	mu      sync.Mutex
	err     error
	closing bool
}

// run accepts and classifies. Classification reads from the connection, so it
// happens in its own goroutine: a slow or silent peer must not hold up every
// other connection behind it on the accept path.
func (l *splitListener) run() {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			l.fail(err)
			return
		}
		go l.classify(conn)
	}
}

// classify reads the request line and routes the connection.
func (l *splitListener) classify(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(headTimeout))
	br := bufio.NewReader(conn)

	line, err := readLine(br, headLimit)
	if err != nil {
		_ = conn.Close()
		return
	}
	query, isTunnel := tunnelQuery(line)
	if !isTunnel {
		// Ordinary HTTP: clear the deadline (net/http sets its own) and replay
		// the request line ahead of the rest of the stream.
		_ = conn.SetReadDeadline(time.Time{})
		l.handOff(&prefixConn{Conn: conn, r: io.MultiReader(bytes.NewReader(line), br)})
		return
	}

	// The tunnel: consume whatever head follows the request line, so the framed
	// packet stream starts on a clean boundary.
	if err := discardHead(br, headLimit); err != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	l.srv.serveTunnel(conn, br, query)
}

// handOff gives a connection to net/http, or closes it if the listener is going
// away with nobody left to accept it.
func (l *splitListener) handOff(conn net.Conn) {
	select {
	case l.accepted <- conn:
	case <-l.done:
		_ = conn.Close()
	}
}

// fail records why accepting stopped and wakes Accept.
func (l *splitListener) fail(err error) {
	l.mu.Lock()
	if l.err == nil {
		l.err = err
	}
	closing := l.closing
	l.closing = true
	l.mu.Unlock()
	if !closing {
		close(l.done)
	}
}

// Accept returns the next connection that is not the tunnel.
func (l *splitListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.accepted:
		return conn, nil
	case <-l.done:
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.err != nil {
			return nil, l.err
		}
		return nil, net.ErrClosed
	}
}

// Close stops accepting. Connections already diverted to the tunnel are the
// server's to close, not the listener's.
func (l *splitListener) Close() error {
	l.mu.Lock()
	closing := l.closing
	l.closing = true
	l.mu.Unlock()
	if !closing {
		close(l.done)
	}
	return l.Listener.Close()
}

// tunnelQuery reports whether a request line asks for the packet tunnel, and
// returns its query string. Anything it cannot parse is not the tunnel, and goes
// to net/http to be rejected there with a proper HTTP error.
func tunnelQuery(line []byte) (query string, ok bool) {
	fields := strings.Fields(strings.TrimRight(string(line), "\r\n"))
	if len(fields) < 2 || fields[0] != http.MethodGet {
		return "", false
	}
	target := fields[1]
	path, query, _ := strings.Cut(target, "?")
	// A gateway may be reached by absolute-form request target; take the path out
	// of it rather than failing to recognise the tunnel.
	if u, err := url.Parse(path); err == nil && u.Path != "" {
		path = u.Path
	}
	if path != PathTunnel {
		return "", false
	}
	return query, true
}

// readLine reads one CRLF-terminated line, including its terminator, refusing
// one longer than limit.
func readLine(br *bufio.Reader, limit int) ([]byte, error) {
	var out []byte
	for {
		b, err := br.ReadByte()
		if err != nil {
			return nil, err
		}
		out = append(out, b)
		if b == '\n' {
			return out, nil
		}
		if len(out) >= limit {
			return nil, io.ErrShortBuffer
		}
	}
}

// discardHead consumes header lines up to and including the blank line that ends
// them. A request line followed immediately by the blank line — which is what the
// reference client sends — ends it at once.
func discardHead(br *bufio.Reader, limit int) error {
	read := 0
	for {
		line, err := readLine(br, limit)
		if err != nil {
			return err
		}
		if s := strings.TrimRight(string(line), "\r\n"); s == "" {
			return nil
		}
		read += len(line)
		if read >= limit {
			return io.ErrShortBuffer
		}
	}
}

// prefixConn is a connection whose reads come from r, so bytes already consumed
// while classifying can be replayed to net/http.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(b []byte) (int, error) { return c.r.Read(b) }
