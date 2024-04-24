package yuubinsya

import (
	"math/rand/v2"
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/crypto"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/plain"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/types"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

var letters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.IntN(len(letters))]
	}
	return b
}

func TestEncode(t *testing.T) {
	auth, err := crypto.GetAuth([]byte("test"))
	assert.NoError(t, err)

	buf := pool.GetBytesWriter(pool.MaxSegmentSize)
	assert.NoError(t, types.EncodePacket(buf, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
		randSeq(rand.IntN(1000)), auth, true))

	t.Log(buf.Bytes())

	data, addr, err := types.DecodePacket(buf.Bytes(), auth, true)
	assert.NoError(t, err)

	t.Log(data, addr)

	plainauth := plain.NewAuth([]byte{1, 2, 3, 4, 5})

	buf = pool.GetBytesWriter(pool.MaxSegmentSize)
	assert.NoError(t, types.EncodePacket(buf,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
		randSeq(rand.IntN(1000)), plainauth, true))

	t.Log(buf.Bytes())

	data, addr, err = types.DecodePacket(buf.Bytes(), plainauth, true)
	assert.NoError(t, err)

	t.Log(data, addr)

	buf = pool.GetBytesWriter(pool.MaxSegmentSize)
	assert.NoError(t, types.EncodePacket(buf,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
		randSeq(rand.IntN(1000)), nil, false))

	t.Log(buf.Bytes())

	data, addr, err = types.DecodePacket(buf.Bytes(), nil, false)
	assert.NoError(t, err)

	t.Log(data, addr)
}
