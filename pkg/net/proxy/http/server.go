package http

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type Server struct {
	netapi.EmptyInterface
	lis          net.Listener
	reverseProxy *httputil.ReverseProxy

	handler            netapi.Handler
	username, password []byte
}

func newServer(o *config.Http, lis net.Listener, handler netapi.Handler) *Server {
	h := &Server{
		username: []byte(o.GetUsername()),
		password: []byte(o.GetPassword()),
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

			go h.handler.HandleStream(sm)

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
		},
	}

	return h
}

//go:linkname ParseBasicAuth net/http.parseBasicAuth
func ParseBasicAuth(auth string) (username, password string, ok bool)

func (h *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if len(h.password) > 0 || len(h.username) > 0 {
		username, password, isHas := ParseBasicAuth(r.Header.Get("Proxy-Authorization"))
		if !isHas {
			w.Header().Set("Proxy-Authenticate", "Basic")
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}

		if (len(h.username) > 0 && subtle.ConstantTimeCompare(unsafe.Slice(unsafe.StringData(username), len(username)), h.username) != 1) ||
			(len(h.password) > 0 && subtle.ConstantTimeCompare(unsafe.Slice(unsafe.StringData(password), len(password)), h.password) != 1) {
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
		source, err = netapi.ParseAddressPort("tcp", req.RemoteAddr, 0)
		if err != nil {
			return err
		}
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
	register.RegisterProtocol(NewServer)
}

func NewServer(o *config.Http, ii netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
	s := newServer(o, ii, handler)

	go func() {
		defer ii.Close()
		if err := http.Serve(ii, s); err != nil {
			log.Error("http serve failed:", err)
		}
	}()

	return s, nil
}
