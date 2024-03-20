package yuubinsya

import (
	"bytes"
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/crypto"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/plain"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/types"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestEncode(t *testing.T) {
	auth, err := crypto.GetAuth([]byte("test"))
	assert.NoError(t, err)

	buf := bytes.NewBuffer(nil)
	assert.NoError(t, types.EncodePacket(buf, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
		[]byte("ssxscsddfscscdsvfsdc sdcs"), auth, true))

	t.Log(buf.Bytes())

	data, addr, err := types.DecodePacket(buf.Bytes(), auth, true)
	assert.NoError(t, err)

	t.Log(data, addr)

	plainauth := plain.NewAuth([]byte{1, 2, 3, 4, 5})

	buf = bytes.NewBuffer(nil)
	assert.NoError(t, types.EncodePacket(buf,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
		[]byte("ssxscsddfscscdsvfsdc sdcs"), plainauth, true))

	t.Log(buf.Bytes())

	data, addr, err = types.DecodePacket(buf.Bytes(), plainauth, true)
	assert.NoError(t, err)

	t.Log(data, addr)

	buf = bytes.NewBuffer(nil)
	assert.NoError(t, types.EncodePacket(buf,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
		[]byte("ssxscsddfscscdsvfsdc sdcs"), nil, false))

	t.Log(buf.Bytes())

	data, addr, err = types.DecodePacket(buf.Bytes(), nil, false)
	assert.NoError(t, err)

	t.Log(data, addr)
}
