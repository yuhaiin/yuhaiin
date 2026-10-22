package hysteria2

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/hysteria2/internal/congestion"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/hysteria2/internal/wire"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
)

type nativeServer struct {
	authenticate                      proxyauth.Verifier
	transport                         *quic.Transport
	listener                          *quic.Listener
	socket                            net.PacketConn
	handler                           netapi.Handler
	password                          string
	upload, download                  uint64
	ignoreClientBandwidth, disableUDP bool
	mu                                sync.Mutex
	connections                       map[*quic.Conn]struct{}
	closing                           bool
	wg                                sync.WaitGroup
	closeOnce                         sync.Once
	closeErr                          error
}

func newNativeServer(socket net.PacketConn, tlsConfig *tls.Config, handler netapi.Handler, password string, upload, download uint64, ignore, disableUDP bool) (*nativeServer, error) {
	tlsConfig = http3.ConfigureTLSConfig(tlsConfig.Clone())
	tr := &quic.Transport{Conn: socket}
	var resetKey quic.StatelessResetKey
	if _, err := rand.Read(resetKey[:]); err != nil {
		_ = socket.Close()
		return nil, err
	}
	tr.StatelessResetKey = &resetKey
	qcfg := &quic.Config{
		InitialStreamReceiveWindow:     8 << 20,
		MaxStreamReceiveWindow:         8 << 20,
		InitialConnectionReceiveWindow: 20 << 20,
		MaxConnectionReceiveWindow:     20 << 20,
		MaxIdleTimeout:                 30 * time.Second,
		MaxIncomingStreams:             1024,
		EnableDatagrams:                true,
		MaxDatagramFrameSize:           wire.MaxDatagram,
		AssumePeerMaxDatagramFrameSize: wire.MaxDatagram,
		DisablePathManager:             true,
	}
	lis, err := tr.Listen(tlsConfig, qcfg)
	if err != nil {
		_ = tr.Close()
		_ = socket.Close()
		return nil, err
	}
	return &nativeServer{transport: tr, listener: lis, socket: socket, handler: handler,
		password: password, upload: upload, download: download,
		ignoreClientBandwidth: ignore, disableUDP: disableUDP,
		connections: make(map[*quic.Conn]struct{})}, nil
}

func (s *nativeServer) Serve() error {
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			return err
		}
		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			_ = conn.CloseWithError(0x100, "")
			return nil
		}
		s.connections[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() { s.mu.Lock(); delete(s.connections, conn); s.mu.Unlock() }()
			s.serveConn(conn)
		}()
	}
}

func (s *nativeServer) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closing = true
		for conn := range s.connections {
			_ = conn.CloseWithError(0x100, "")
		}
		s.mu.Unlock()
		s.closeErr = errors.Join(s.listener.Close(), s.transport.Close(), s.socket.Close())
		s.wg.Wait()
	})
	return s.closeErr
}

func (s *nativeServer) serveConn(conn *quic.Conn) {
	h := &nativeHTTPHandler{server: s, conn: conn}
	h3 := &http3.Server{Handler: h, StreamDispatcher: h.dispatchStream}
	_ = h3.ServeQUICConn(conn)
	h.mu.Lock()
	h.closing = true
	udp := h.udp
	h.mu.Unlock()
	_ = conn.CloseWithError(0x100, "")
	if h.authStop != nil {
		h.authStop()
	}
	h.requests.Wait()
	if udp != nil {
		udp.closeAll()
	}
}

type nativeHTTPHandler struct {
	identity               *proxyauth.Identity
	authStop               func() bool
	server                 *nativeServer
	conn                   *quic.Conn
	mu                     sync.Mutex
	authenticated, closing bool
	requests               sync.WaitGroup
	udp                    *nativeServerUDP
}

func (h *nativeHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Host != wire.AuthHost || r.URL.Path != wire.AuthPath {
		http.NotFound(w, r)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closing {
		http.NotFound(w, r)
		return
	}
	if !h.authenticated {
		auth := wire.ReadClientAuth(r.Header)
		identity, err := proxyauth.Check(r.Context(), h.server.authenticate, "", []byte(auth.Password), "", h.server.password)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		h.identity = identity
		if identity != nil {
			h.authStop = context.AfterFunc(identity.Context, func() { _ = h.conn.CloseWithError(0x100, "") })
		}
		h.authenticated = true
		tx := auth.ReceiveBytesPerSecond
		if h.server.upload > 0 && tx > h.server.upload {
			tx = h.server.upload
		}
		if h.server.ignoreClientBandwidth || tx == 0 {
			congestion.UseConfigured(h.conn, "", "")
		} else {
			congestion.UseBrutal(h.conn, tx, false)
		}
		if !h.server.disableUDP {
			h.udp = newNativeServerUDP(h.conn, netapi.WithIdentityHandler(h.server.handler, h.identity))
			go h.udp.run()
		}
	}
	if err := wire.WriteServerAuth(w.Header(), wire.ServerAuth{
		UDPEnabled:            !h.server.disableUDP,
		ReceiveBytesPerSecond: h.server.download,
		AutoBandwidth:         h.server.ignoreClientBandwidth,
	}); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(wire.AuthOK)
}

func (h *nativeHTTPHandler) dispatchStream(frame http3.FrameType, stream *quic.Stream, incomingErr error) (bool, error) {
	if incomingErr != nil || frame != wire.FrameTCPRequest {
		return false, nil
	}
	h.mu.Lock()
	allowed := h.authenticated && !h.closing
	if allowed {
		h.requests.Add(1)
	}
	h.mu.Unlock()
	if !allowed {
		return false, nil
	}
	// StreamDispatcher peeks at the HTTP/3 stream type; consume that prefix.
	if v, err := quicvarint.Read(quicvarint.NewReader(stream)); err != nil || v != wire.FrameTCPRequest {
		h.requests.Done()
		if err != nil {
			return false, err
		}
		return false, fmt.Errorf("hysteria2: incorrect TCP frame")
	}
	go func() { defer h.requests.Done(); h.handleTCP(stream) }()
	return true, nil
}

func (h *nativeHTTPHandler) handleTCP(stream *quic.Stream) {
	// A handler may hand the stream to another goroutine. It owns the stream
	// after dispatch, just as it does for the other inbound protocols.
	handedOff := false
	defer func() {
		if !handedOff {
			stream.CancelRead(0)
			_ = stream.Close()
		}
	}()
	addr, err := wire.ReadTCPRequestBody(stream)
	if err != nil {
		stream.CancelRead(0)
		return
	}
	destination, err := netapi.ParseAddress("tcp", addr)
	if err != nil {
		_ = wire.WriteTCPResponse(stream, false, "invalid destination")
		return
	}
	if err := wire.WriteTCPResponse(stream, true, "Connected"); err != nil {
		return
	}
	conn := &nativeTCPConn{Stream: stream, local: h.conn.LocalAddr(), remote: h.conn.RemoteAddr()}
	handedOff = true
	netapi.WithIdentityHandler(h.server.handler, h.identity).HandleStream(&netapi.StreamMeta{
		Source: h.conn.RemoteAddr(), Destination: destination, Inbound: h.conn.LocalAddr(),
		Src: conn, Address: destination,
	})
}

var _ http.Handler = (*nativeHTTPHandler)(nil)
