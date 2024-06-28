package dns

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
)

func TestDNSJson(t *testing.T) {
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		ad, err := netapi.ParseAddress(network, addr)
		if err != nil {
			return nil, fmt.Errorf("parse address failed: %w", err)
		}
		return socks5.Dial("127.0.0.1", "1080", "", "").Conn(ctx, ad)
	}
	t.Log(DOHJsonAPI("https://dns.google/resolve", "dict.hjenglish.com", dialContext))
	t.Log(DOHJsonAPI("https://dns.google/resolve", "i0.hdslb.com", dialContext))
}
