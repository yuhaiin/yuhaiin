package client

import (
	"bytes"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestResolveAddr(t *testing.T) {
	z := ParseAddr(netapi.ParseAddressPort(0, "a.com", netapi.ParsePort(51)))
	t.Log(z)

	addr, err := ResolveAddr(bytes.NewReader(z))
	assert.NoError(t, err)
	t.Log(addr)
	t.Log(addr.Address(0))
}
