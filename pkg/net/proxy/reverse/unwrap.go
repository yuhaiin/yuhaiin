package reverse

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	contractgateway "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func init() {
	register.RegisterContractPoint("http_termination", func(config contractnode.HTTPTermination, p netapi.Proxy) (netapi.Proxy, error) {
		return NewHttpTermination(httpTerminationConfigFromContract(config), p)
	})
}

func httpTerminationConfigFromContract(config contractnode.HTTPTermination) Config {
	out := Config{Headers: make(map[string]HTTPHeaders, len(config.Headers))}
	for name, headers := range config.Headers {
		out.Headers[name] = httpHeadersFromContract(headers)
	}
	if len(out.Headers) == 0 {
		out.Headers = nil
	}
	return out
}

func httpHeadersFromContract(headers contractnode.HTTPHeaders) HTTPHeaders {
	out := HTTPHeaders{Headers: make([]HTTPHeader, 0, len(headers.Headers))}
	for _, header := range headers.Headers {
		out.Headers = append(out.Headers, HTTPHeader{
			Key:   header.Key,
			Value: header.Value,
		})
	}
	return out
}

type httpTermination struct {
	netapi.Proxy
	ch     *netapi.ChannelStreamListener
	server *http.Server
	engine *gateway.Engine
}

type Config struct {
	Headers map[string]HTTPHeaders `json:"headers,omitzero"`
}

type HTTPHeaders struct {
	Headers []HTTPHeader `json:"headers,omitzero"`
}

type HTTPHeader struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// NewHttpTermination remains an outbound-chain adapter. TLS ownership is typed
// connection metadata; no address strings are modified to carry protocol state.
func NewHttpTermination(c Config, p netapi.Proxy) (netapi.Proxy, error) {
	ch := netapi.NewChannelStreamListener(netapi.EmptyAddr)
	var rules []contractgateway.Rule
	for domain, headers := range c.Headers {
		requestHeaders := make(map[string][]string)
		for _, header := range headers.Headers {
			requestHeaders[header.Key] = []string{header.Value}
		}
		name := strings.TrimPrefix(domain, "*.")
		rules = append(rules, contractgateway.Rule{ID: domain, Name: domain, Enabled: true, Priority: -len(name), Match: contractgateway.Condition{Field: "host", Operator: "domain", Value: name}, Action: contractgateway.Action{Type: "forward", Rewrite: contractgateway.Rewrite{Headers: requestHeaders}}})
	}
	engine, err := gateway.NewEngine(contractgateway.Gateway{ID: "legacy-termination", Enabled: true, Default: contractgateway.Action{Type: "forward"}}, rules, nil, func(ctx context.Context, a netapi.Address, _ contractroute.Target) (gateway.Selection, error) {
		state, _ := ctx.Value(terminationKey{}).(*terminationState)
		terminated := state != nil && state.tls.Load()
		return gateway.Selection{Identity: fmt.Sprintf("legacy-termination:%p", p), Proxy: p, Destination: a, TLSAlreadyTerminated: terminated}, nil
	})
	if err != nil {
		_ = ch.Close()
		return nil, err
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	server := &http.Server{ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, Protocols: protocols, ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
		return context.WithValue(ctx, terminationKey{}, conn.(*terminationServerConn).state)
	}}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, _ := r.Context().Value(terminationKey{}).(*terminationState)
		if state == nil {
			http.Error(w, "missing termination metadata", http.StatusInternalServerError)
			return
		}
		scheme := "http"
		if state.tls.Load() {
			scheme = "https"
		}
		original := netapi.ForkContext(context.WithValue(state.context, terminationKey{}, state))
		engine.ServeHTTP(w, r.WithContext(gateway.WithMetadata(r.Context(), gateway.Metadata{Context: original, OriginalDestination: state.destination, Authority: state.destination.Hostname(), Scheme: scheme})))
	})
	go func() { _ = server.Serve(ch) }()
	return &httpTermination{Proxy: p, ch: ch, server: server, engine: engine}, nil
}

type terminationKey struct{}
type terminationState struct {
	tls         atomic.Bool
	context     context.Context
	destination netapi.Address
}
type terminationServerConn struct {
	*pipe.Conn
	state *terminationState
}
type wrapConn struct {
	*pipe.Conn
	state *terminationState
}

func (w *wrapConn) SetTLSTermination(ok bool) { w.state.tls.Store(ok) }
func (u *httpTermination) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	left, right := pipe.Pipe()
	state := &terminationState{context: netapi.ForkContext(context.WithoutCancel(ctx)), destination: addr}
	u.ch.NewConn(&terminationServerConn{Conn: left, state: state})
	return &wrapConn{Conn: right, state: state}, nil
}
func (u *httpTermination) Close() error {
	return errors.Join(u.ch.Close(), u.server.Close(), u.engine.Close(), u.Proxy.Close())
}
