package shadowsocks

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

/*
 from https://github.com/Dreamacro/clash/blob/master/component/simple-obfs/http.go
*/
// HTTPObfs is shadowsocks http simple-obfs implementation
type HTTPObfs struct {
	net.Conn
	host          string
	port          string
	buf           []byte
	offset        int
	firstRequest  bool
	firstResponse bool
}

func (ho *HTTPObfs) Read(b []byte) (int, error) {
	if ho.buf != nil {
		n := copy(b, ho.buf[ho.offset:])
		ho.offset += n
		if ho.offset == len(ho.buf) {
			ho.buf = nil
		}
		return n, nil
	}

	if ho.firstResponse {
		buf := pool.GetBytes(pool.DefaultSize)
		defer pool.PutBytes(buf)
		n, err := ho.Conn.Read(buf)
		if err != nil {
			// utils.BuffPool(pool.DefaultSize).Put(&(buf))
			return 0, err
		}
		idx := bytes.Index(buf[:n], []byte("\r\n\r\n"))
		if idx == -1 {
			// utils.BuffPool(pool.DefaultSize).Put(&(buf))
			return 0, io.EOF
		}
		ho.firstResponse = false
		length := n - (idx + 4)
		n = copy(b, buf[idx+4:n])
		if length > n {
			ho.buf = buf[:idx+4+length]
			ho.offset = idx + 4 + n
		} else {
			// utils.BuffPool(pool.DefaultSize).Put(&(buf))
		}
		return n, nil
	}
	return ho.Conn.Read(b)
}

func (ho *HTTPObfs) Write(b []byte) (int, error) {
	if ho.firstRequest {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/", ho.host), bytes.NewBuffer(b[:]))
		req.Header.Set("User-Agent", fmt.Sprintf("curl/7.%d.%d", rand.Int()%54, rand.Int()%2))
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		req.Host = fmt.Sprintf("%s:%s", ho.host, ho.port)
		req.Header.Set("Sec-WebSocket-Key", base64.URLEncoding.EncodeToString([]byte(time.Now().String()[:16])))
		req.ContentLength = int64(len(b))
		err := req.Write(ho.Conn)
		ho.firstRequest = false
		return len(b), err
	}

	return ho.Conn.Write(b)
}

// newHTTPObfs return a HTTPObfs
func newHTTPObfs(conn net.Conn, host string, port string) net.Conn {
	return &HTTPObfs{
		Conn:          conn,
		firstRequest:  true,
		firstResponse: true,
		host:          host,
		port:          port,
	}
}

var _ netapi.Proxy = (*httpOBFS)(nil)

type httpOBFS struct {
	netapi.Proxy
	host string
	port string
}

func init() {
	point.RegisterProtocol(NewHTTPOBFS)
}

func NewHTTPOBFS(config *protocol.Protocol_ObfsHttp) point.WrapProxy {
	return func(p netapi.Proxy) (netapi.Proxy, error) {
		return &httpOBFS{
			host:  config.ObfsHttp.Host,
			port:  config.ObfsHttp.Port,
			Proxy: p,
		}, nil
	}
}

func (h *httpOBFS) Conn(ctx context.Context, s netapi.Address) (net.Conn, error) {
	conn, err := h.Proxy.Conn(ctx, s)
	if err != nil {
		return nil, err
	}
	return newHTTPObfs(conn, h.host, h.port), nil
}
