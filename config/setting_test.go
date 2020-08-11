package config

import (
	"os"
	"os/exec"
	"path"
	"testing"

	"github.com/golang/protobuf/jsonpb"
)

func TestSettingDecodeJSON(t *testing.T) {
	s, err := SettingDecodeJSON()
	if err != nil {
		t.Error(err)
	}
	t.Log(s, s.HTTPHost, s.DNSProxy)

	//err = SettingEnCodeJSON(s)
	//if err != nil {
	//	t.Error(err)
	//}
}

func TestJsonPb(t *testing.T) {
	m := jsonpb.Marshaler{Indent: "\t"}
	s := &Setting{
		DOH:       true,
		DnsServer: "127.0.0.1:1080",
	}
	data, err := m.MarshalToString(s)
	if err != nil {
		t.Error(err)
	}
	t.Log(data)

	s2 := &Setting{}
	err = jsonpb.UnmarshalString(data, s2)
	if err != nil {
		t.Error(err)
	}
	t.Log(s2, s2.HTTPHost)

	s3 := &Setting{}
	err = jsonpb.UnmarshalString(` {
        	"is_dns_over_https": true,
			"sss":"sss",
        	"dnsServer": "127.0.0.1:1080"
        }`, s3)
	if err != nil {
		t.Log(err)
	}
	t.Log(s3)
}

func TestCreatDir(t *testing.T) {
_retry:
	file, err := os.OpenFile("./b/a/a.txt", os.O_TRUNC|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		if os.IsNotExist(err) {
			t.Log(path.Dir("./b/a/a.txt"))
			err = os.MkdirAll(path.Dir("./b/a/a.txt"), os.ModePerm)
			if err != nil {
				t.Error(err)
			}
			goto _retry
		}
		t.Error(err)
	}
	defer file.Close()
	t.Log(file.WriteString("test"))
}

func TestCmd(t *testing.T) {
	process, err := os.FindProcess(11192)
	if err != nil {
		t.Log(err)
	}
	cmd := exec.Command("", "")
	cmd.Process = process
	err = cmd.Wait()
	if err != nil {
		t.Error(err)
	}
	//err = cmd.Process.Kill()
	//if err != nil {
	//	t.Error(err)
	//}
}
