package subscr

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/subscr/utils"
)

func TestInt2str(t *testing.T) {
	t.Log(utils.I2String(nil))
	t.Log(utils.I2String("a"))
}
