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

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

func init() {
	register.RegisterPoint(NewHttpTermination)
}

type httpTermination struct {
	netapi.Proxy
	ch *netapi.ChannelStreamListener
}

func NewHttpTermination(c *protocol.HttpTermination, p netapi.Proxy) (netapi.Proxy, error) {
	ch := netapi.NewChannelStreamListener(netapi.EmptyAddr)

	headers := trie.NewTrie[*protocol.HttpTerminationHttpHeaders]()

	for k, v := range c.GetHeaders() {
		headers.Insert(k, v)
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
			ctx := netapi.WithContext(context.TODO())

			addr, _ := netapi.ParseAddress("tcp", pr.Host)

			if v, ok := headers.Search(trie.OnlyMatchFqdn(ctx), addr); ok {
				for _, v := range v.GetHeaders() {
					pr.Header.Set(v.GetKey(), v.GetValue())
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
	tlsTermination bool
	netapi.DomainAddr
}

func (u *unWrapHttpAddr) SetTLSTermination(ok bool) { u.tlsTermination = ok }

func (u *unWrapHttpAddr) String() string {
	return fmt.Sprintf("tlsTermination:%v", u.tlsTermination)
}
