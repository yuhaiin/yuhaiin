package httpproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
	_ "unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type Server struct {
	username, password string
	inbound            net.Addr
	reverseProxy       *httputil.ReverseProxy

	ctx   context.Context
	close context.CancelFunc

	tcpChannel chan *netapi.StreamMeta

	lis listener.InboundI
}

func newServer(o *listener.Inbound_Http, inbound net.Addr) *Server {
	ctx, cancel := context.WithCancel(context.TODO())

	h := &Server{
		username:   o.Http.Username,
		password:   o.Http.Password,
		inbound:    inbound,
		ctx:        ctx,
		close:      cancel,
		tcpChannel: make(chan *netapi.StreamMeta, 100),
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

			select {
			case <-h.ctx.Done():
				return nil, h.ctx.Err()
			case h.tcpChannel <- &netapi.StreamMeta{
				Source:      source,
				Inbound:     h.inbound,
				Destination: address,
				Src:         local,
				Address:     address,
			}:
			}

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

	client, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return fmt.Errorf("hijack failed: %w", err)
	}

	source, err := netapi.ParseAddress(statistic.Type_tcp, req.RemoteAddr)
	if err != nil {
		source = netapi.ParseAddressPort(statistic.Type_tcp, req.RemoteAddr, netapi.EmptyPort)
	}

	select {
	case <-h.ctx.Done():
		return h.ctx.Err()
	case h.tcpChannel <- &netapi.StreamMeta{
		Inbound:     h.inbound,
		Source:      source,
		Src:         client,
		Destination: dst,
		Address:     dst,
	}:
	}
	return nil
}

func (s *Server) AcceptPacket() (*netapi.Packet, error) {
	return nil, io.EOF
}

func (s *Server) AcceptStream() (*netapi.StreamMeta, error) {
	select {
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case meta := <-s.tcpChannel:
		return meta, nil
	}
}

func (s *Server) Close() error {
	s.close()
	if s.lis != nil {
		return s.lis.Close()
	}

	return nil
}

func init() {
	listener.RegisterProtocol2(NewServer)
}

func NewServer(o *listener.Inbound_Http) func(listener.InboundI) (netapi.ProtocolServer, error) {
	return func(ii listener.InboundI) (netapi.ProtocolServer, error) {
		s := newServer(o, ii.Addr())

		go func() {
			defer ii.Close()
			if err := http.Serve(ii, s); err != nil {
				log.Error("http serve failed:", err)
			}
		}()

		return s, nil
	}
}
