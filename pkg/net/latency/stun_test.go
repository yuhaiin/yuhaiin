package latency

import (
	"context"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestStun(t *testing.T) {
	store := netapi.WithContext(context.TODO())
	store.ConnOptions().SetSkipRoute(true)
	t.Log(0x04 | 0x02)

	store.ConnOptions().Resolver().SetMode(netapi.ResolverModePreferIPv4)

	t.Log(StunTCP(store, direct.Default, "stun.nextcloud.com:443"))

	resolver, err := resolver.New(resolver.Config{
		Type: config.Type_doh,
		Host: "1.1.1.1",
	})
	assert.NoError(t, err)

	ip, err := resolver.LookupIP(store, "stun.nextcloud.com")
	assert.NoError(t, err)

	t.Log(Stun(store, direct.Default, ip.Rand().String()))
}
