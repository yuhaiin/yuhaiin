package shadowsocks

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
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
		buf := utils.GetBytes(utils.DefaultSize)
		defer utils.PutBytes(buf)
		n, err := ho.Conn.Read(buf)
		if err != nil {
			// utils.BuffPool(utils.DefaultSize).Put(&(buf))
			return 0, err
		}
		idx := bytes.Index(buf[:n], []byte("\r\n\r\n"))
		if idx == -1 {
			// utils.BuffPool(utils.DefaultSize).Put(&(buf))
			return 0, io.EOF
		}
		ho.firstResponse = false
		length := n - (idx + 4)
		n = copy(b, buf[idx+4:n])
		if length > n {
			ho.buf = buf[:idx+4+length]
			ho.offset = idx + 4 + n
		} else {
			// utils.BuffPool(utils.DefaultSize).Put(&(buf))
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

var _ proxy.Proxy = (*httpOBFS)(nil)

type httpOBFS struct {
	host string
	port string
	p    proxy.Proxy
}

func NewHTTPOBFS(config *node.PointProtocol_ObfsHttp) node.WrapProxy {
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		return &httpOBFS{
			host: config.ObfsHttp.Host,
			port: config.ObfsHttp.Port,
			p:    p,
		}, nil
	}
}

func (h *httpOBFS) Conn(s string) (net.Conn, error) {
	conn, err := h.p.Conn(s)
	if err != nil {
		return nil, err
	}
	return newHTTPObfs(conn, h.host, h.port), nil
}

func (h *httpOBFS) PacketConn(s string) (net.PacketConn, error) {
	return h.p.PacketConn(s)
}
