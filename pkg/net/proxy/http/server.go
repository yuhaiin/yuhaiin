package httpproxy

import (
	"context"
	"errors"
	"fmt"
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

type server struct {
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

	h := &server{
		username: o.Protocol.Http.Username,
		password: o.Protocol.Http.Password,
		inbound:  lis.Addr(),
		handler:  o.Handler,
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
			if !errors.Is(err, context.Canceled) {
				log.Error("http: proxy error: ", err)
			}
			w.WriteHeader(http.StatusBadGateway)
		},
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out = pr.Out.WithContext(context.WithValue(pr.Out.Context(), remoteKey{}, pr.In.RemoteAddr))
			pr.Out.RequestURI = ""
		},
	}

	go func() {
		defer lis.Close()
		if err := http.Serve(lis, h); err != nil {
			log.Error("http serve failed:", err)
		}
	}()
	return lis, nil
}

//go:linkname parseBasicAuth net/http.parseBasicAuth
func parseBasicAuth(auth string) (username, password string, ok bool)

func (h *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
		h.connect(w, r)
	default:
		h.reverseProxy.ServeHTTP(w, r)
	}
}

func (h *server) connect(w http.ResponseWriter, req *http.Request) error {
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

/*
func verifyUserPass(user, key string, client net.Conn, req *http.Request) error {
	if user == "" || key == "" {
		return nil
	}
	username, password, isHas := parseBasicAuth(req.Header.Get("Proxy-Authorization"))
	if !isHas {
		_, _ = client.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"))
		return errors.New("proxy Authentication Required")
	}
	if username != user || password != key {
		_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		return errors.New("user or password verify failed")
	}
	return nil
}

type HTTP struct {
	dialer             netapi.Proxy
	username, password string
}

func (h *HTTP) dial(conn net.Conn, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.TODO(), time.Second*5)
	defer cancel()

	address, err := netapi.ParseAddress(statistic.Type_tcp, addr)
	if err != nil {
		return nil, fmt.Errorf("parse address failed: %w", err)
	}

	address.WithValue(proxy.InboundKey{}, conn.LocalAddr())
	address.WithValue(netapi.SourceKey{}, conn.RemoteAddr())
	address.WithValue(netapi.DestinationKey{}, address)

	return h.dialer.Conn(ctx, address)
}

func (h *HTTP) handshake(conn net.Conn) {

	tr := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return h.dial(conn, addr)
		},
	}
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()

	err := h.handle(h.username, h.password, conn, client)
	if err != nil && !errors.Is(err, io.EOF) {
		if errors.Is(err, proxy.ErrBlocked) {
			log.Debug(err.Error())
		} else {
			log.Error("http server handle failed", "err", err)
		}
	}
}

func (h *HTTP) handle(user, key string, src net.Conn, client *http.Client) error {

	// use golang http

	defer src.Close()
	reader := bufio.NewReader(src)

_start:
	req, err := http.ReadRequest(reader)
	if err != nil {
		return fmt.Errorf("read request failed: %w", err)
	}

	err = verifyUserPass(user, key, src, req)
	if err != nil {
		return fmt.Errorf("http verify user pass failed: %w", err)
	}

	if req.Method == http.MethodConnect {
		return h.connect(src, req)
	}

	keepAlive := strings.TrimSpace(strings.ToLower(req.Header.Get("Proxy-Connection"))) == "keep-alive"

	if err = normal(src, client, req, keepAlive); err != nil {
		// only have resp write error
		return nil
	}

	if keepAlive {
		goto _start
	}

	return nil
}


func (h *HTTP) connect(client net.Conn, req *http.Request) error {
	host := req.URL.Host
	if req.URL.Port() == "" {
		host = net.JoinHostPort(host, "80")
	}

	dst, err := h.dial(client, host)
	if err != nil {
		er := respError(http.StatusBadGateway, req).Write(client)
		if er != nil {
			err = fmt.Errorf("%v\nresp 503 failed: %w", err, er)
		}
		return fmt.Errorf("get conn [%s] from proxy failed: %w", host, err)
	}
	defer dst.Close()

	_, err = fmt.Fprintf(client, "HTTP/%d.%d 200 Connection established\r\n\r\n", req.ProtoMajor, req.ProtoMinor)
	if err != nil {
		return fmt.Errorf("write to client failed: %w", err)
	}
	relay.Relay(dst, client)
	return nil
}

func normal(src net.Conn, client *http.Client, req *http.Request, keepAlive bool) error {
	modifyRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		log.Error("http client do failed", "err", err)
		resp = respError(http.StatusBadGateway, req)
	} else {
		defer resp.Body.Close()
		modifyResponse(resp, keepAlive)
	}

	err = resp.Write(src)
	if err != nil {
		return fmt.Errorf("resp write failed: %w", err)
	}

	return nil
}

func modifyRequest(req *http.Request) {
	if len(req.URL.Host) > 0 {
		req.Host = req.URL.Host
	}

	// Prevent UA from being set to golang's default ones
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "")
	}

	req.RequestURI = ""
	req.Header.Set("Connection", "close")
	removeHeader(req.Header)
}

func modifyResponse(resp *http.Response, keepAlive bool) {
	removeHeader(resp.Header)

	resp.Close = true
	if keepAlive && (resp.ContentLength >= 0) {
		resp.Header.Set("Proxy-Connection", "keep-alive")
		resp.Header.Set("Connection", "Keep-Alive")
		resp.Header.Set("Keep-Alive", "timeout=4")
		resp.Close = false
	}
}

func respError(code int, req *http.Request) *http.Response {
	// RFC 2068 (HTTP/1.1) requires URL to be absolute URL in HTTP proxy.
	response := &http.Response{
		Status:        http.StatusText(code),
		StatusCode:    code,
		Proto:         req.Proto,
		ProtoMajor:    req.ProtoMajor,
		ProtoMinor:    req.ProtoMinor,
		Header:        http.Header(make(map[string][]string)),
		Body:          nil,
		ContentLength: 0,
		Close:         true,
	}
	response.Header.Set("Proxy-Connection", "close")
	response.Header.Set("Connection", "close")
	return response
}

func removeHeader(h http.Header) {
	connections := h.Get("Connection")
	h.Del("Connection")
	if len(connections) != 0 {
		for _, x := range strings.Split(connections, ",") {
			h.Del(strings.TrimSpace(x))
		}
	}
	h.Del("Proxy-Connection")
	h.Del("Proxy-Authenticate")
	h.Del("Proxy-Authorization")
	h.Del("TE")
	h.Del("Trailers")
	h.Del("Transfer-Encoding")
	h.Del("Upgrade")
}

func NewServer(o *listener.Opts[*listener.Protocol_Http]) (iserver.Server, error) {
	lis, err := dialer.ListenContext(context.TODO(), "tcp", o.Protocol.Http.Host)
	if err != nil {
		return nil, err
	}

	h := &HTTP{
		dialer:   o.Dialer,
		username: o.Protocol.Http.Username,
		password: o.Protocol.Http.Password,
	}

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				log.Error("accept failed", "err", err)
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					continue
				}
				return
			}

			go func() {
				defer conn.Close()
				h.handshake(conn)
			}()
		}
	}()
	return lis, nil
}
*/
