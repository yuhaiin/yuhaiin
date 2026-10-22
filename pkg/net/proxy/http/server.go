package http

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

type Server struct {
	netapi.EmptyInterface
	lis          net.Listener
	reverseProxy *httputil.ReverseProxy

	authenticate       proxyauth.Verifier
	handler            netapi.Handler
	username, password []byte
}

type ServerConfig struct {
	Authenticate proxyauth.Verifier `json:"-"`
	Username     string             `json:"username,omitzero"`
	Password     string             `json:"password,omitzero"`
}

func newServer(o ServerConfig, lis net.Listener, handler netapi.Handler) *Server {
	h := &Server{
		authenticate: o.Authenticate,
		username:     []byte(o.Username),
		password:     []byte(o.Password),
		lis:          lis,
		handler:      handler,
	}

	type remoteKey struct{}

	tr := &http.Transport{
		DisableKeepAlives:     o.Authenticate != nil,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			address, err := netapi.ParseAddress(network, addr)
			if err != nil {
				return nil, fmt.Errorf("parse address failed: %w", err)
			}

			remoteAddr, _ := ctx.Value(remoteKey{}).(string)

			source, err := netapi.ParseAddress(network, remoteAddr)
			if err != nil {
				source, err = netapi.ParseAddressPort(network, remoteAddr, 0)
				if err != nil {
					return nil, err
				}
			}

			local, remote := pipe.Pipe()

			sm := &netapi.StreamMeta{
				Source:      source,
				Inbound:     h.lis.Addr(),
				Destination: address,
				Src:         local,
				Address:     address,
			}

			go netapi.WithIdentityHandler(h.handler, netapi.TrafficIdentity(ctx)).HandleStream(sm)

			return remote, nil
		},
	}

	h.reverseProxy = &httputil.ReverseProxy{
		Transport:  tr,
		BufferPool: pool.ReverseProxyBuffer{},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if err != nil && !errors.Is(err, context.Canceled) {
				log.Error("http: proxy error: ", "err", err, "remote", r.RemoteAddr)
			}
			w.WriteHeader(http.StatusBadGateway)
		},
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out = pr.Out.WithContext(context.WithValue(pr.Out.Context(), remoteKey{}, pr.In.RemoteAddr))
			pr.Out.RequestURI = ""
			pr.Out.Header.Del("Proxy-Authorization")
		},
	}

	return h
}

func ParseBasicAuth(auth string) (username, password string, ok bool) {
	r := &http.Request{Header: http.Header{"Authorization": {auth}}}
	return r.BasicAuth()
}

func (h *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if h.authenticate != nil || len(h.password) > 0 || len(h.username) > 0 {
		username, password, present := ParseBasicAuth(r.Header.Get("Proxy-Authorization"))
		if !present {
			w.Header().Set("Proxy-Authenticate", "Basic")
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		identity, err := proxyauth.Check(r.Context(), h.authenticate, username, []byte(password), string(h.username), string(h.password))
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if identity != nil {
			ctx, cancel := context.WithCancel(netapi.WithTrafficIdentity(r.Context(), identity))
			defer cancel()
			stop := context.AfterFunc(identity.Context, cancel)
			defer stop()
			r = r.WithContext(ctx)
		}
	}

	switch r.Method {
	case http.MethodConnect:
		if err := h.connect(w, r); err != nil {
			log.Error("connect failed", "err", err)
		}
	default:
		h.reverseProxy.ServeHTTP(w, r)
	}
}

func (h *Server) connect(w http.ResponseWriter, req *http.Request) error {
	host := req.URL.Host
	if req.URL.Port() == "" {
		switch req.URL.Scheme {
		case "http":
			host = net.JoinHostPort(host, "80")
		case "https":
			host = net.JoinHostPort(host, "443")
		}
	}

	dst, err := netapi.ParseAddress("tcp", host)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return fmt.Errorf("parse address failed: %w", err)
	}

	source, err := netapi.ParseAddress("tcp", req.RemoteAddr)
	if err != nil {
		source, err = netapi.ParseAddressPort("tcp", req.RemoteAddr, 0)
		if err != nil {
			return err
		}
	}
	client, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return fmt.Errorf("hijack failed: %w", err)
	}
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = client.Close()
		return err
	}
	if err := buffered.Flush(); err != nil {
		_ = client.Close()
		return err
	}
	// CONNECT may arrive in the same packet as ClientHello or application data.
	// Hijack's reader owns those bytes; replay them before reading the socket.
	client = &hijackedConn{Conn: client, reader: buffered.Reader}

	sm := &netapi.StreamMeta{
		Source:      source,
		Inbound:     h.lis.Addr(),
		Destination: dst,
		Src:         client,
		Address:     dst,
	}

	netapi.WithIdentityHandler(h.handler, netapi.TrafficIdentity(req.Context())).HandleStream(sm)
	return nil
}

type hijackedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *hijackedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (s *Server) AcceptPacket() (*netapi.Packet, error) {
	return nil, io.EOF
}

func (s *Server) Close() error {
	if s.lis != nil {
		return s.lis.Close()
	}

	return nil
}

func NewServer(o ServerConfig, ii netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
	s := newServer(o, ii, handler)
	// CONNECT tunnels use HTTP/1 hijacking, regardless of the TLS transport's ALPN.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	server := &http.Server{Handler: s, Protocols: protocols}

	go func() {
		defer ii.Close()
		if err := server.Serve(netapi.WithoutTLSMetadata(ii)); err != nil {
			log.Error("http serve failed:", err)
		}
	}()

	return s, nil
}
