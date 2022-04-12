package config

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestJsonPb(t *testing.T) {
	s := &config.Setting{
		SystemProxy: &config.SystemProxy{
			Http:   true,
			Socks5: false,
		},
		Bypass: &config.Bypass{
			Enabled:    true,
			BypassFile: filepath.Join("/tmp/yuhaiin/setting", "yuhaiin.conf"),
		},
		Proxy: &config.Proxy{},
		Dns: &config.DnsSetting{
			Remote: &config.Dns{
				Host:   "cloudflare-dns.com",
				Type:   config.Dns_doh,
				Proxy:  false,
				Subnet: "0.0.0.0/32",
			},
			Local: &config.Dns{
				Host: "223.5.5.5",
				Type: config.Dns_doh,
			},
		},
	}
	data, err := protojson.MarshalOptions{Multiline: true, Indent: "\t"}.Marshal(s)
	if err != nil {
		t.Error(err)
	}
	t.Log(string(data))

	s2 := &config.Setting{}
	err = protojson.Unmarshal([]byte(data), s2)
	if err != nil {
		t.Error(err)
	}
	t.Log(s2, s2.Proxy)

	s3 := &config.Setting{}
	err = protojson.UnmarshalOptions{DiscardUnknown: true, AllowPartial: true}.Unmarshal([]byte(`{"system_proxy":{"enabled":true,"http":true,"unknowTest":""}}`), s3)
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
