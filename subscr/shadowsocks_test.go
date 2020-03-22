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
	//url,err := url.Parse(string(bytes.Split(dst,[]byte{'\n'})[0]))
	//if err != nil{
	//	t.Log(err)
	//}
	//server := url.Hostname()
	//port := url.Port()
	//method := strings.Split(base64d.Base64d(url.User.String()),":")[0]
	//password := strings.Split(base64d.Base64d(url.User.String()),":")[1]
	//group := url.Query()["group"][0]
	//plugin := url.Query()["plugin"][0]
	//name := url.Fragment
	//t.Log(server)
	//t.Log(port)
	//t.Log(method)
	//t.Log(password)
	//t.Log(plugin)
	//t.Log(group)
	//t.Log(name)
	//t.Log(url.Scheme,url.Query(),url.Hostname(),url.Port(),url.User,url.Fragment)
}
