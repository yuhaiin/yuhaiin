package config

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"

	"github.com/golang/protobuf/jsonpb"
)

var (
	Path    string
	ConPath string
)

func init() {
	var err error
	Path, err = os.UserConfigDir()
	if err == nil {
		Path = path.Join(Path, "yuhaiin")
		goto _end
	}
	{
		file, err := exec.LookPath(os.Args[0])
		if err != nil {
			log.Println(err)
			Path = "./yuhaiin"
			goto _end
		}
		execPath, err := filepath.Abs(file)
		if err != nil {
			log.Println(err)
			Path = "./yuhaiin"
			goto _end
		}
		Path = path.Join(filepath.Dir(execPath), "config")
	}
_end:
	ConPath = path.Join(Path, "yuhaiinConfig.json")
}

// SettingDecodeJSON decode setting json to struct
func SettingDecodeJSON() (*Setting, error) {
	pa := &Setting{
		BypassFile: path.Join(Path, "yuhaiin.conf"),
		DnsServer:  "cloudflare-dns.com",
		DnsSubNet:  "0.0.0.0/32",
		Bypass:     true,
		HTTPHost:   "127.0.0.1:8188",
		Socks5Host: "127.0.0.1:1080",
		RedirHost:  "127.0.0.1:8088",
		DOH:        true,
		DNSProxy:   false,
		SsrPath:    "",
		BlackIcon:  false,
		DirectDNS: &DirectDNS{
			Host: "223.5.5.5",
			DOH:  true,
		},
	}
	data, err := ioutil.ReadFile(ConPath)
	if err != nil {
		if os.IsNotExist(err) {
			return pa, SettingEnCodeJSON(pa)
		}
		return pa, fmt.Errorf("read config file failed: %v", err)
	}
	err = jsonpb.UnmarshalString(string(data), pa)
	return pa, err
}

// SettingEnCodeJSON encode setting struct to json
func SettingEnCodeJSON(pa *Setting) error {
	_, err := os.Stat(ConPath)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(path.Dir(ConPath), os.ModePerm)
			if err != nil {
				return fmt.Errorf("SettingEncodeJson():MkdirAll -> %v", err)
			}
		}
		return fmt.Errorf("SettingEncodeJson -> %v", err)
	}
	data, err := (&jsonpb.Marshaler{Indent: "\t"}).MarshalToString(pa)
	if err != nil {
		return fmt.Errorf("marshal() -> %v", err)
	}
	return ioutil.WriteFile(ConPath, []byte(data), os.ModePerm)
}
