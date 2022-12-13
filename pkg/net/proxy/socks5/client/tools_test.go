package client

import (
	"bytes"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestResolveAddr(t *testing.T) {
	z := ParseAddr(proxy.ParseAddressSplit("", "a.com", proxy.ParsePort(51)))
	t.Log(z)

	addr, err := ResolveAddr(bytes.NewReader(z))
	assert.NoError(t, err)
	t.Log(addr)
	t.Log(addr.Address(""))
}
