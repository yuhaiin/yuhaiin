package httpproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
	_ "unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type Server struct {
	username, password string
	inbound            net.Addr
	reverseProxy       *httputil.ReverseProxy
	handler            netapi.Handler
}

func NewServer(o *listener.Opts[*listener.Protocol_Http]) (netapi.Server, error) {
	lis, err := dialer.ListenContext(context.TODO(), "tcp", o.Protocol.Http.Host)
	if err != nil {
		return nil, err
	}

	return NewServerWithListener(lis, o), nil
}

func newServer(o *listener.Opts[*listener.Protocol_Http], inbound net.Addr) *Server {
	h := &Server{
		username: o.Protocol.Http.Username,
		password: o.Protocol.Http.Password,
		handler:  o.Handler,
		inbound:  inbound,
	}

	type remoteKey struct{}

	tr := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			address, err := netapi.ParseAddress(statistic.Type_tcp, addr)
			if err != nil {
				return nil, fmt.Errorf("parse address failed: %w", err)
			}

			remoteAddr, _ := ctx.Value(remoteKey{}).(string)

			source, err := netapi.ParseAddress(statistic.Type_tcp, remoteAddr)
			if err != nil {
				source = netapi.ParseAddressPort(statistic.Type_tcp, remoteAddr, netapi.EmptyPort)
			}

			local, remote := net.Pipe()
			o.Handler.Stream(ctx, &netapi.StreamMeta{
				Source:      source,
				Inbound:     h.inbound,
				Destination: address,
				Src:         local,
				Address:     address,
			})

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

func NewServerWithListener(lis net.Listener, o *listener.Opts[*listener.Protocol_Http]) netapi.Server {
	h := newServer(o, lis.Addr())

	go func() {
		defer lis.Close()
		if err := http.Serve(lis, h); err != nil {
			log.Error("http serve failed:", err)
		}
	}()
	return lis
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
			slog.Error("connect failed", "err", err)
		}
	default:
		h.reverseProxy.ServeHTTP(w, r)
	}
}

func (h *Server) connect(w http.ResponseWriter, req *http.Request) error {
	host := req.URL.Host
	if req.URL.Port() == "" {
		host = net.JoinHostPort(host, "80")
	}

	dst, err := netapi.ParseAddress(statistic.Type_tcp, host)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return fmt.Errorf("parse address failed: %w", err)
	}

	w.WriteHeader(http.StatusOK)

	hj, ok := w.(http.Hijacker)
	if !ok {
		return errors.New("http.ResponseWriter does not implement http.Hijacker")
	}

	client, _, err := hj.Hijack()
	if err != nil {
		return fmt.Errorf("hijack failed: %w", err)

	}

	source, err := netapi.ParseAddress(statistic.Type_tcp, req.RemoteAddr)
	if err != nil {
		source = netapi.ParseAddressPort(statistic.Type_tcp, req.RemoteAddr, netapi.EmptyPort)
	}

	h.handler.Stream(context.TODO(), &netapi.StreamMeta{
		Inbound:     h.inbound,
		Source:      source,
		Src:         client,
		Destination: dst,
		Address:     dst,
	})
	return nil
}

type HandleServer struct {
	netapi.Server
	chanLis *netapi.ChannelListener
}

func NewServerHandler(o *listener.Opts[*listener.Protocol_Http], inbound net.Addr) *HandleServer {
	cl := netapi.NewChannelListener(inbound)

	return &HandleServer{NewServerWithListener(cl, o), cl}
}
func (h *HandleServer) Handle(c net.Conn) error {
	h.chanLis.NewConn(c)
	return nil
}
