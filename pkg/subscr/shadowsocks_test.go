package subscr

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"testing"
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
	dst, err := DecodeBytesBase64(s)
	if err != nil {
		t.Log(err)
	}
	t.Log(string(bytes.Split(dst, []byte{'\n'})[0]))
	log.Println((&shadowsocks{}).ParseLink(bytes.Split(dst, []byte{'\n'})[0]))
}
