package reverse

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

func init() {
	register.RegisterProtocol(NewHTTPServer)
}

func NewHTTPServer(o *listener.ReverseHttp, ii netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
	uri, err := url.Parse(o.GetUrl())
	if err != nil {
		return nil, err
	}

	lis, err := ii.Stream(context.TODO())
	if err != nil {
		return nil, err
	}

	if o.GetTls() != nil {
		o.GetTls().SetEnable(true)
	}

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
				source = netapi.ParseAddressPort(network, remoteAddr, 0)
			}

			local, remote := pipe.Pipe()

			sm := &netapi.StreamMeta{
				Source:      source,
				Inbound:     lis.Addr(),
				Destination: address,
				Src:         local,
				Address:     address,
			}

			handler.HandleStream(sm)
			return remote, nil
		},

		TLSClientConfig: tls.ParseTLSConfig(o.GetTls()),
	}

	go func() {
		if err := http.Serve(lis, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Debug("reverse http serve", "host", r.Host, "method", r.Method, "path", r.URL.Path, "target", o.GetUrl())

			r = r.WithContext(context.WithValue(r.Context(), remoteKey{}, r.RemoteAddr))
			rp.ServeHTTP(w, r)
		})); err != nil {
			log.Error("reverse http serve failed", "err", err)
		}
	}()

	return lis, nil
}
