package mock

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	shttp "github.com/Asutorufa/yuhaiin/pkg/net/sniff/http"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

func init() {
	register.RegisterPoint(NewClient)
	register.RegisterTransport(NewServer)
}

var mockData = "GET / HTTP/1.1\r\nHost: www.speedtest.cn\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"

type client struct {
	netapi.Proxy
}

func NewClient(config *protocol.HttpMock, p netapi.Proxy) (netapi.Proxy, error) {
	return &client{Proxy: p}, nil
}

func (h *client) Conn(ctx context.Context, s netapi.Address) (net.Conn, error) {
	conn, err := h.Proxy.Conn(ctx, s)
	if err != nil {
		return nil, err
	}

	_, err = conn.Write([]byte(mockData))
	if err != nil {
		return nil, err
	}

	return conn, nil
}

type server struct {
	netapi.Listener
}

func (s *server) Stream(ctx context.Context) (net.Listener, error) {
	lis, err := s.Listener.Stream(ctx)
	if err != nil {
		return nil, err
	}

	return &listenerWrap{Listener: lis}, nil
}

func NewServer(config *listener.HttpMock, lis netapi.Listener) (netapi.Listener, error) {
	return &server{Listener: lis}, nil
}

type listenerWrap struct {
	net.Listener
}

func (s *listenerWrap) Accept() (net.Conn, error) {
	conn, err := s.Listener.Accept()
	if err != nil {
		return nil, err
	}

	bufconn := pool.NewBufioConnSize(conn, configuration.SnifferBufferSize)

	err = bufconn.BufioRead(func(br *bufio.Reader) error {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second * 30))
		_, err := br.ReadByte()
		_ = conn.SetReadDeadline(time.Time{})
		if err == nil {
			_ = br.UnreadByte()
		}

		buf, _ := br.Peek(br.Buffered())

		i := bytes.IndexByte(buf, ' ')
		if i == -1 {
			return nil
		}

		if !shttp.Methods[unsafe.String(unsafe.SliceData(buf[:i]), len(buf[:i]))] {
			return nil
		}

		req, err := http.ReadRequest(br)
		fmt.Println(req.URL, req.Host, req.Header, err)
		return err
	})
	if err != nil {
		bufconn.Close()
		return nil, err
	}

	return bufconn, nil
}
