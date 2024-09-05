package sniff

import (
	"bufio"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/sniff/bittorrent"
	"github.com/Asutorufa/yuhaiin/pkg/net/sniff/http"
	"github.com/Asutorufa/yuhaiin/pkg/net/sniff/tls"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type entry[T any] struct {
	checker func(*netapi.Context, []byte) bool
	name    string
	enabled bool
}

type Sniffier[T any] struct {
	streamChecker []entry[T]
	packetChecker []entry[T]
}

func New() *Sniffier[bypass.Mode] {
	return &Sniffier[bypass.Mode]{
		streamChecker: []entry[bypass.Mode]{
			{
				enabled: true,
				name:    "tls",
				checker: func(ctx *netapi.Context, b []byte) bool {
					ctx.TLSServerName = tls.Sniff(b)
					if ctx.TLSServerName != "" {
						ctx.Protocol = "tls"
						return true
					}
					return false
				},
			},
			{
				enabled: true,
				name:    "http",
				checker: func(ctx *netapi.Context, b []byte) bool {
					ctx.HTTPHost = http.Sniff(b)
					if ctx.HTTPHost != "" {
						ctx.Protocol = "http"
						return true
					}
					return false
				},
			},
			{
				enabled: true,
				name:    "bittorrent",
				checker: func(ctx *netapi.Context, b []byte) bool {
					_, err := bittorrent.SniffBittorrent(b)
					if err == nil {
						ctx.Protocol = "bittorrent"
						ctx.SniffMode = bypass.Mode_direct
						return true
					}

					return false
				},
			},
		},

		packetChecker: []entry[bypass.Mode]{
			{
				enabled: true,
				name:    "bittorrent_utp",
				checker: func(ctx *netapi.Context, b []byte) bool {
					_, err := bittorrent.SniffUTP(b)
					if err == nil {
						ctx.Protocol = "bittorrent_utp"
						ctx.SniffMode = bypass.Mode_direct
						return true
					}

					return false
				},
			},
		},
	}
}

func (s *Sniffier[T]) Packet(ctx *netapi.Context, b []byte) {
	for _, c := range s.packetChecker {
		if !c.enabled {
			continue
		}
		if c.checker(ctx, b) {
			return
		}
	}
}

func (s *Sniffier[T]) Stream(ctx *netapi.Context, cc net.Conn) net.Conn {
	c := pool.NewBufioConnSize(cc, pool.MaxSegmentSize)

	var buf []byte

	_ = c.BufioRead(func(br *bufio.Reader) error {
		n, _ := br.Read([]byte{0x00})
		if n > 0 {
			_ = br.UnreadByte()
		}

		buf, _ = br.Peek(br.Buffered())
		return nil
	})

	if len(buf) == 0 {
		return c
	}

	for _, ck := range s.streamChecker {
		if !ck.enabled {
			continue
		}
		if ck.checker(ctx, buf) {
			return c
		}
	}

	return c
}
