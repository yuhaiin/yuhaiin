package reverse

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	ptls "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	sniffhttp "github.com/Asutorufa/yuhaiin/pkg/net/sniff/http"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func init() {
	register.RegisterProtocol(NewHTTPServer)
}

func NewHTTPServer(o *config.ReverseHttp, ii netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
	uri, err := url.Parse(o.GetUrl())
	if err != nil {
		return nil, err
	}

	if o.GetTls() != nil {
		o.GetTls().SetEnable(true)
	}

	tlsConfig := ptls.ParseTLSConfig(o.GetTls())

	httpch := netapi.NewChannelStreamListener(ii.Addr())
	go func() {
		defer httpch.Close()

		ii := netapi.NewErrCountListener(ii, 10)
		for {
			conn, err := ii.Accept()
			if err != nil {
				log.Error("reverse http accept failed", "err", err)
				break
			}

			go func() {
				c := pool.NewBufioConnSize(conn, configuration.SnifferBufferSize)

				var buf []byte
				_ = c.BufioRead(func(br *bufio.Reader) error {
					_ = c.SetReadDeadline(time.Now().Add(time.Millisecond * 55))
					_, err := br.ReadByte()
					_ = c.SetReadDeadline(time.Time{})
					if err == nil {
						_ = br.UnreadByte()
					}

					buf, _ = br.Peek(br.Buffered())
					return nil
				})

				if len(buf) == 0 || sniffhttp.Sniff(buf) != "" {
					httpch.NewConn(c)
					return
				}

				defer c.Close()

				host := uri.Host
				_, _, err := net.SplitHostPort(uri.Host)
				if err != nil {
					host = net.JoinHostPort(uri.Host, "443")
				}

				address, err := netapi.ParseAddress("tcp", host)
				if err != nil {
					log.Error("parse address failed", "err", err)
				}

				sm := &netapi.StreamMeta{
					Source:      c.RemoteAddr(),
					Inbound:     ii.Addr(),
					Destination: address,
					Src:         c,
					Address:     address,
				}

				handler.HandleStream(sm)
			}()
		}
	}()

	type remoteKey struct{}
	rp := httputil.NewSingleHostReverseProxy(uri)
	rp.BufferPool = pool.ReverseProxyBuffer{}
	rp.Transport = &http.Transport{
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
				Inbound:     ii.Addr(),
				Destination: address,
				Src:         local,
				Address:     address,
			}

			go handler.HandleStream(sm)
			return remote, nil
		},

		TLSClientConfig: tlsConfig,
	}

	go func() {
		if err := http.Serve(httpch, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Debug("reverse http serve", "host", r.Host, "method", r.Method, "path", r.URL.Path, "target", o.GetUrl())

			r = r.WithContext(context.WithValue(r.Context(), remoteKey{}, r.RemoteAddr))
			rp.ServeHTTP(w, r)
		})); err != nil {
			log.Error("reverse http serve failed", "err", err)
		}
	}()

	return &accepter{Listener: ii}, nil
}

type accepter struct {
	netapi.EmptyInterface
	net.Listener
}
