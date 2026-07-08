package server

import (
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/schema/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestServer(t *testing.T) {
	t.Skip("starts a long-running DNS server and depends on external DoH service")

	z, err := resolver.New(resolver.Config{Type: config.Type_doh, Host: "223.5.5.5"})
	assert.NoError(t, err)

	s := NewServer("127.0.0.1:5353", z)
	defer s.Close()
	time.Sleep(time.Minute * 5)
}
