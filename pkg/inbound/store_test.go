package inbound

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/schema/config"
)

func TestInboundItemNameUsesStoreKey(t *testing.T) {
	item := inboundItem("openwrt", config.Inbound_builder{
		Name:   new("tproxy"),
		Tproxy: &config.Tproxy{},
	}.Build())

	if got := item.GetName(); got != "openwrt" {
		t.Fatalf("inbound item name = %q, want store key %q", got, "openwrt")
	}
}
