package subscr

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

func TestShadowSocks(t *testing.T) {
	f, err := os.Open("/home/asutorufa/Desktop/node.txt")
	if err != nil {
		t.Log(err)
	}
	s, err := ioutil.ReadAll(f)
	if err != nil {
		t.Log(err)
	}
	dst, err := Base64d2(s)
	if err != nil {
		t.Log(err)
	}
	t.Log(string(bytes.Split(dst, []byte{'\n'})[0]))
	log.Println(ShadowSocksParse(bytes.Split(dst, []byte{'\n'})[0]))
}
