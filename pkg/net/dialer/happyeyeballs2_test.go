package dialer

import (
	"context"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestDial(t *testing.T) {
	addr, err := netapi.ParseDomainPort("tcp", "ip-3-86-108-113-ext.gold0028.gameloft.com", 46267)
	assert.NoError(t, err)
	conn, err := DialHappyEyeballsv2(context.TODO(), addr)
	assert.NoError(t, err)
	defer conn.Close()
	t.Log(conn.LocalAddr(), conn.RemoteAddr())

	var buf [1024]byte
	_, err = conn.Read(buf[:])
	assert.NoError(t, err)
	t.Log(string(buf[:]))
}
