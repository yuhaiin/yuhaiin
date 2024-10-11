package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
	_ "unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type Server struct {
	lis          net.Listener
	reverseProxy *httputil.ReverseProxy

	handler            netapi.Handler
	username, password string
}

func newServer(o *listener.Inbound_Http, lis net.Listener, handler netapi.Handler) *Server {
	h := &Server{
		username: o.Http.Username,
		password: o.Http.Password,
		lis:      lis,
		handler:  handler,
	}

	type remoteKey struct{}

	tr := &http.Transport{
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
				source = netapi.ParseAddressPort(network, remoteAddr, 0)
			}

			local, remote := net.Pipe()

			sm := &netapi.StreamMeta{
				Source:      source,
				Inbound:     h.lis.Addr(),
				Destination: address,
				Src:         local,
				Address:     address,
			}

			h.handler.HandleStream(sm)

			return remote, nil
		},
	}

	h.reverseProxy = &httputil.ReverseProxy{
		Transport:  tr,
		BufferPool: pool.ReverseProxyBuffer{},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if err != nil && !errors.Is(err, context.Canceled) {
				log.Error("http: proxy error: ", "err", err)
			}
			w.WriteHeader(http.StatusBadGateway)
		},
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out = pr.Out.WithContext(context.WithValue(pr.Out.Context(), remoteKey{}, pr.In.RemoteAddr))
			pr.Out.RequestURI = ""
		},
	}

	return h
}

//go:linkname parseBasicAuth net/http.parseBasicAuth
func parseBasicAuth(auth string) (username, password string, ok bool)

func (h *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if h.password != "" || h.username != "" {
		username, password, isHas := parseBasicAuth(r.Header.Get("Proxy-Authorization"))
		if !isHas {
			w.Header().Set("Proxy-Authenticate", "Basic")
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}

		if username != h.username || password != h.password {
			w.WriteHeader(http.StatusForbidden)
			return
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

	w.WriteHeader(http.StatusOK)

	client, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return fmt.Errorf("hijack failed: %w", err)
	}

	source, err := netapi.ParseAddress("tcp", req.RemoteAddr)
	if err != nil {
		source = netapi.ParseAddressPort("tcp", req.RemoteAddr, 0)
	}

	sm := &netapi.StreamMeta{
		Source:      source,
		Inbound:     h.lis.Addr(),
		Destination: dst,
		Src:         client,
		Address:     dst,
	}

	h.handler.HandleStream(sm)
	return nil
}

func (s *Server) AcceptPacket() (*netapi.Packet, error) {
	return nil, io.EOF
}

func (s *Server) Close() error {
	if s.lis != nil {
		return s.lis.Close()
	}

	return nil
}

func init() {
	listener.RegisterProtocol(NewServer)
}

func NewServer(o *listener.Inbound_Http) func(netapi.Listener, netapi.Handler) (netapi.Accepter, error) {
	return func(ii netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
		lis, err := ii.Stream(context.TODO())
		if err != nil {
			return nil, err
		}

		s := newServer(o, lis, handler)

		go func() {
			defer ii.Close()
			if err := http.Serve(lis, s); err != nil {
				log.Error("http serve failed:", err)
			}
		}()

		return s, nil
	}
}
