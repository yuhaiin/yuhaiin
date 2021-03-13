package config

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"

	"google.golang.org/protobuf/encoding/protojson"
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
		SsrPath: "",
		SystemProxy: &SystemProxy{
			Enabled: true,
			HTTP:    true,
			Socks5:  false,
			// linux system set socks5 will make firfox websocket can't connect
			// https://askubuntu.com/questions/890274/slack-desktop-client-on-16-04-behind-proxy-server
		},
		Bypass: &Bypass{
			Enabled:    true,
			BypassFile: path.Join(Path, "yuhaiin.conf"),
		},
		Proxy: &Proxy{
			HTTP:   "127.0.0.1:8188",
			Socks5: "127.0.0.1:1080",
			Redir:  "127.0.0.1:8088",
		},
		DNS: &DNS{
			Host:   "cloudflare-dns.com",
			DOH:    true,
			Proxy:  false,
			Subnet: "0.0.0.0/32",
		},
		LocalDNS: &DNS{
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
	err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, pa)
	return pa, err
}

// SettingEnCodeJSON encode setting struct to json
func SettingEnCodeJSON(pa *Setting) error {
	_, err := os.Stat(ConPath)
	if err != nil && os.IsNotExist(err) {
		err = os.MkdirAll(path.Dir(ConPath), os.ModePerm)
		if err != nil {
			return fmt.Errorf("make dir failed: %v", err)
		}
	}

	data, err := protojson.MarshalOptions{Multiline: true, Indent: "\t"}.Marshal(pa)
	if err != nil {
		return fmt.Errorf("marshal setting failed: %v", err)
	}

	return ioutil.WriteFile(ConPath, []byte(data), os.ModePerm)
}
