package nat

import (
	"encoding/binary"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"golang.org/x/crypto/blake2b"
)

var serviceStartTime = func() []byte {
	return binary.BigEndian.AppendUint64(nil, uint64(system.NowUnix()))
}()

func GenerateID(src net.Addr) uint64 {
	b2b, err := blake2b.New(8, serviceStartTime)
	if err != nil {
		panic(err)
	}
	b2b.Write([]byte(src.String()))
	return binary.BigEndian.Uint64(b2b.Sum(nil))
}
