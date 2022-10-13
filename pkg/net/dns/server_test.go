package dns

import (
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
)

func TestServer(t *testing.T) {
	z := New(Config{Type: dns.Type_doh, Host: "223.5.5.5"}).(*doh)
	s := NewDnsServer("127.0.0.1:5353", proxy.WrapDNS(z))
	defer s.Close()
	time.Sleep(time.Minute * 5)
}
