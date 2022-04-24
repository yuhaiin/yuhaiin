package trojan

import (
	"bytes"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

func TestXxx(t *testing.T) {
	b := utils.GetBytes(200)

	buf := bytes.NewBuffer(b)
	buf.Reset()

	buf.WriteString("abcd")
	buf.WriteString("abcde")

	t.Log(buf.Bytes())
}
