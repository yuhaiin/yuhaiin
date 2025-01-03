package latency

import (
	"context"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestStun(t *testing.T) {
	store := netapi.WithContext(context.TODO())
	t.Log(0x04 | 0x02)

	store.SkipRoute = true
	store.Resolver.Mode = netapi.ResolverModePreferIPv4

	t.Log(StunTCP(store, direct.Default, "stun.nextcloud.com:443"))

	resolver, err := dns.New(dns.Config{
		Type: pd.Type_doh,
		Host: "1.1.1.1",
	})
	assert.NoError(t, err)

	ip, err := resolver.LookupIP(store, "stun.nextcloud.com")
	assert.NoError(t, err)

	t.Log(Stun(store, direct.Default, ip[0].String()))
}
