package route

import (
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"testing"
)

func TestProbeKeepsFixedOutboundAndAppliesBlockAfterGateway(t *testing.T) {
	for _, mode := range []string{"block", "proxy", "direct"} {
		t.Run(mode, func(t *testing.T) {
			router := gatewayRoute(t, alwaysRule("http-service", "gateway", contract.Target{Type: "gateway", ID: "g"}), alwaysRule("probe-policy", mode, contract.Target{Type: "selector", ID: "recursive-selector"}))
			ctx := netapi.WithContext(t.Context())
			a, _ := netapi.ParseAddress("tcp", "probe.example.invalid:443")
			result, err := router.PrepareProbe(ctx, a)
			if mode == "block" {
				if !netapi.IsBlockError(err) {
					t.Fatal(err)
				}
			} else if err != nil || result.String() != a.String() {
				t.Fatal(result, err)
			}
			if d := router.d.(*gatewayTestDialer); d.mode != "" || d.target.Type != "" {
				t.Fatal("probe recursively selected an outbound", d)
			}
			id, _ := ctx.MatchedRule()
			if id != "probe-policy" {
				t.Fatal("lost route identity", id)
			}
		})
	}
}
