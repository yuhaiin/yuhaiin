package reverse

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	ptls "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
)

type HTTPServerConfig struct {
	URL string         `json:"url"`
	TLS ptls.TLSConfig `json:"tls,omitzero"`
}

// NewHTTPServer adapts persisted reverse_http listeners to the shared Gateway
// engine. Existing non-HTTP/TLS passthrough and explicitly configured TLS options
// remain supported; managed gateways use their independent verified profiles.
func NewHTTPServer(o HTTPServerConfig, ii netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
	uri, err := url.Parse(o.URL)
	if err != nil || uri == nil || (uri.Scheme != "http" && uri.Scheme != "https") || uri.Hostname() == "" {
		return nil, errors.New("reverse_http requires an HTTP or HTTPS upstream URL")
	}
	engine, err := gateway.NewEngine(contract.Gateway{ID: "legacy-reverse", Enabled: true, Default: contract.Action{Type: "reverse_proxy", Upstream: "legacy", PreserveHost: true}}, nil, []contract.Upstream{{ID: "legacy", Backends: []contract.Backend{{URL: o.URL}}}},
		func(_ context.Context, a netapi.Address, _ route.Target) (gateway.Selection, error) {
			return gateway.Selection{Identity: "legacy-handler", Proxy: handlerProxy{handler: handler, inbound: ii.Addr()}, Destination: a}, nil
		}, gateway.WithClientTLS(ptls.ParseTLSConfig(o.TLS)))
	if err != nil {
		return nil, err
	}
	channel := netapi.NewChannelStreamListener(ii.Addr())
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	protocols.SetUnencryptedHTTP2(true)
	server := &http.Server{Handler: engine, Protocols: protocols, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		state := netapi.WithContext(ctx)
		state.Source = c.RemoteAddr()
		state.SetInbound(ii.Addr())
		return state
	}}
	go func() { _ = server.Serve(channel) }()
	port := uri.Port()
	if port == "" {
		port = "80"
		if uri.Scheme == "https" {
			port = "443"
		}
	}
	destination, err := netapi.ParseAddress("tcp", net.JoinHostPort(uri.Hostname(), port))
	if err != nil {
		_ = server.Close()
		_ = engine.Close()
		return nil, err
	}
	go func() {
		defer channel.Close()
		for {
			conn, err := ii.Accept()
			if err != nil {
				return
			}
			go func() {
				if _, ok := conn.(*tls.Conn); ok {
					channel.NewConn(conn)
					return
				}
				reader := bufio.NewReaderSize(conn, 4096)
				_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
				first, err := reader.Peek(1)
				_ = conn.SetReadDeadline(time.Time{})
				buffered := &legacyReaderConn{Conn: conn, reader: reader}
				if err == nil && !strings.ContainsRune("GHPDOTC", rune(first[0])) {
					handler.HandleStream(&netapi.StreamMeta{Source: conn.RemoteAddr(), Inbound: ii.Addr(), Destination: destination, Address: destination, Src: buffered})
					return
				}
				channel.NewConn(buffered)
			}()
		}
	}()
	return &legacyHTTPServer{listener: ii, server: server, engine: engine, channel: channel}, nil
}

type handlerProxy struct {
	netapi.Proxy
	handler netapi.Handler
	inbound net.Addr
}

func (p handlerProxy) Conn(ctx context.Context, a netapi.Address) (net.Conn, error) {
	local, remote := pipe.Pipe()
	state := netapi.GetContext(ctx)
	go p.handler.HandleStream(&netapi.StreamMeta{Source: state.Source, Inbound: p.inbound, Destination: a, Address: a, Src: local, InboundName: state.GetInboundName(), InboundID: state.GetInboundID()})
	return remote, nil
}

type legacyReaderConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *legacyReaderConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

type legacyHTTPServer struct {
	netapi.EmptyInterface
	listener netapi.Listener
	server   *http.Server
	engine   *gateway.Engine
	channel  *netapi.ChannelStreamListener
}

func (s *legacyHTTPServer) Close() error {
	return errors.Join(s.listener.Close(), s.channel.Close(), s.server.Close(), s.engine.Close())
}

type accepter struct {
	netapi.EmptyInterface
	net.Listener
}
