package reverse

import (
	"bufio"
	"crypto/tls"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/sniff/http"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

type Hijack struct {
	config *tls.Config
}

func (h *Hijack) Stream(ctx *netapi.Context, src net.Conn) (net.Conn, error) {
	protocol := ctx.GetProtocol()
	if protocol != "tls" && protocol != "http" {
		return src, nil
	}

	if protocol == "tls" {
		src = tls.Server(src, h.config)

		c := pool.NewBufioConnSize(src, configuration.SnifferBufferSize)

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

		if len(buf) == 0 {
			return c, nil
		}

		if http.Sniff(buf) == "" {
			return c, nil
		}

		src = c
	}

	return src, nil
}
