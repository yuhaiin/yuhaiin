package shadowsocksr

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/subscr/utils"
)

func TestSsrParse2(t *testing.T) {
	ssr := []string{"ssr://MS4xLjEuMTo1MzphdXRoX2NoYWluX2E6bm9uZTpodHRwX3NpbXBsZTo2YUtkNW9HcDZMcXIvP29iZnNwYXJhbT02YUtkNW9HcDZMcXImcHJvdG9wYXJhbT02YUtkNW9HcDZMcXImcmVtYXJrcz02YUtkNW9HcDZMcXImZ3JvdXA9NmFLZDVvR3A2THFy",
		"ssr://MS4xLjEuMTo1MzphdXRoX2NoYWluX2E6bm9uZTpodHRwX3NpbXBsZTo2YUtkNW9HcDZMcXIvP29iZnNwYXJhbT02YUtkNW9HcDZMcXImcHJvdG9wYXJhbT02YUtkNW9HcDZMcXImcmVtYXJrcz1jMlZqYjI1ayZncm91cD02YUtkNW9HcDZMcXIK",
		"ssr://MS4xLjEuMTo1MzphdXRoX2NoYWluX2E6bm9uZTpodHRwX3NpbXBsZTo2YUtkNW9HcDZMcXIvP29iZnNwYXJhbT02YUtkNW9HcDZMcXImcHJvdG9wYXJhbT02YUtkNW9HcDZMcXImcmVtYXJrcz1jM056YzNOeiZncm91cD1jM056YzNOego",
		"ssr://MjIyLjIyMi4yMjIuMjIyOjQ0MzphdXRoX2FlczEyOF9tZDU6Y2hhY2hhMjAtaWV0ZjpodHRwX3Bvc3Q6ZEdWemRBby8/b2Jmc3BhcmFtPWRHVnpkQW8mcHJvdG9wYXJhbT1kR1Z6ZEFvJnJlbWFya3M9ZEdWemRBbyZncm91cD1kR1Z6ZEFvCg"}

	for x := range ssr {
		log.Println(ParseLink([]byte(ssr[x]), "test"))
	}
}

func TestLint(t *testing.T) {
	f, err := os.Open("/node_ssr.txt")
	if err != nil {
		t.Log(err)
	}
	s, err := ioutil.ReadAll(f)
	if err != nil {
		t.Log(err)
	}
	dst, err := utils.DecodeBytesBase64(s)
	if err != nil {
		t.Log(err)
	}
	for _, x := range bytes.Split(dst, []byte("\n")) {
		log.Println(ParseLink(x, "test"))
	}
}
