package config

import (
	"fmt"
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
	file, err := os.Open(ConPath)
	if err != nil {
		if os.IsNotExist(err) {
			return pa, SettingEnCodeJSON(pa)
		}
		return pa, err
	}
	defer file.Close()
	if jsonpb.Unmarshal(file, pa) != nil {
		log.Println(err)
	}
	return pa, nil
}

// SettingEnCodeJSON encode setting struct to json
func SettingEnCodeJSON(pa *Setting) error {
_retry:
	file, err := os.OpenFile(ConPath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(path.Dir(ConPath), os.ModePerm)
			if err != nil {
				return fmt.Errorf("SettingEncodeJson():MkdirAll -> %v", err)
			}
			goto _retry
		}
		return fmt.Errorf("SettingEncodeJson -> %v", err)
	}
	defer file.Close()
	m := jsonpb.Marshaler{Indent: "\t"}
	err = m.Marshal(file, pa)
	if err != nil {
		return fmt.Errorf("marshal() -> %v", err)
	}
	return err
}
