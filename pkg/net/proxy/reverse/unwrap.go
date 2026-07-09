package reverse

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
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
	ch *netapi.ChannelStreamListener
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

func NewHttpTermination(c Config, p netapi.Proxy) (netapi.Proxy, error) {
	ch := netapi.NewChannelStreamListener(netapi.EmptyAddr)

	headers := trie.NewTrie[*HTTPHeaders]()

	for k := range c.Headers {
		v := c.Headers[k]
		headers.Insert(k, &v)
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			add, err := netapi.ParseAddress(network, addr)
			if err != nil {
				return nil, err
			}

			return p.Conn(ctx, add)
		},
	}

	type tlsTerminationKey struct{}

	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if ctx.Value(tlsTerminationKey{}) == true {
			return tr.DialContext(ctx, network, addr)
		}

		conn, err := tr.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		return tls.Client(conn, tr.TLSClientConfig), nil
	}

	hr := &httputil.ReverseProxy{
		Transport:  tr,
		BufferPool: pool.ReverseProxyBuffer{},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if err != nil && !errors.Is(err, context.Canceled) {
				log.Error("http: proxy error: ", "err", err)
			}
			w.WriteHeader(http.StatusBadGateway)
		},
		Director: func(pr *http.Request) {
			addr, _ := netapi.ParseAddress("tcp", pr.Host)

			if v, ok := headers.SearchFqdn(addr); ok {
				for _, v := range v.Headers {
					pr.Header.Set(v.Key, v.Value)
				}
			}

			var defaultScheme string
			if strings.HasSuffix(pr.RemoteAddr, "tlsTermination:true") {
				defaultScheme = "https"
				pr.RemoteAddr = strings.TrimSuffix(pr.RemoteAddr, "tlsTermination:true")
				*pr = *pr.WithContext(context.WithValue(pr.Context(), tlsTerminationKey{}, true))
			} else {
				defaultScheme = "http"
			}

			pr.RequestURI = ""
			pr.URL.Scheme = defaultScheme
			pr.URL.Host = pr.Host
		},
	}

	go func() {
		defer ch.Close()

		s := http.Server{
			Handler: hr,
		}

		err := s.Serve(ch)
		if err != nil {
			log.Warn("reverse proxy error", "err", err)
		}
	}()

	return &httpTermination{
		Proxy: p,
		ch:    ch,
	}, nil
}

func (u *httpTermination) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	p1, p2 := pipe.Pipe()

	uw := &unWrapHttpAddr{}

	p1.SetRemoteAddr(uw)

	u.ch.NewConn(p1)

	return &wrapConn{p2, uw}, nil
}

func (u *httpTermination) Close() error {
	u.ch.Close()
	return u.Proxy.Close()
}

type wrapConn struct {
	*pipe.Conn
	uw *unWrapHttpAddr
}

func (w *wrapConn) SetTLSTermination(ok bool) { w.uw.SetTLSTermination(ok) }

type unWrapHttpAddr struct {
	netapi.DomainAddr
	tlsTermination bool
}

func (u *unWrapHttpAddr) SetTLSTermination(ok bool) { u.tlsTermination = ok }

func (u *unWrapHttpAddr) String() string {
	return fmt.Sprintf("tlsTermination:%v", u.tlsTermination)
}
