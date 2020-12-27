package shadowsocks

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/Asutorufa/yuhaiin/subscr/common"
)

func TestShadowSocks(t *testing.T) {
	f, err := os.Open("node.txt")
	if err != nil {
		t.Log(err)
	}
	s, err := ioutil.ReadAll(f)
	if err != nil {
		t.Log(err)
	}
	dst, err := common.Base64DByte(s)
	if err != nil {
		t.Log(err)
	}
	t.Log(string(bytes.Split(dst, []byte{'\n'})[0]))
	log.Println(ParseLink(bytes.Split(dst, []byte{'\n'})[0], "test"))
}
