package statistics

import (
	"encoding/base64"
	"encoding/binary"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/unit"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

func TestXxx(t *testing.T) {
	t.Log(unit.ReducedUnit(float64(binary.BigEndian.Uint64(yerror.Ignore(base64.RawStdEncoding.DecodeString("AAAAC9JgHpkK"))))))
}
