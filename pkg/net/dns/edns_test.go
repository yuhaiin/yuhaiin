package dns

import (
	"net"
	"testing"
)

func TestMask(t *testing.T) {
	_, s, err := net.ParseCIDR("ff::1/20")
	if err != nil {
		t.Error(err)
	}
	t.Log(s.Mask.Size())
	t.Log(s.IP)

}
