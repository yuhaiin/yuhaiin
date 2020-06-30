package config

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"path"

	"github.com/golang/protobuf/jsonpb"
)

var (
	usr, _        = user.Current()
	pathSeparator = string(os.PathSeparator)
	ConPath       = Path + pathSeparator + "yuhaiinConfig.json"
)

// SettingDecodeJSON decode setting json to struct
func SettingDecodeJSON() (*Setting, error) {
	file, err := os.Open(ConPath)
	if err != nil {
		if os.IsNotExist(err) {
			pa := &Setting{
				BypassFile:         Path + pathSeparator + "yuhaiin.conf",
				DnsServer:          "cloudflare-dns.com",
				DnsSubNet:          "0.0.0.0/32",
				Bypass:             true,
				HttpProxyAddress:   "127.0.0.1:8188",
				Socks5ProxyAddress: "127.0.0.1:1080",
				RedirProxyAddress:  "127.0.0.1:8088",
				IsDNSOverHTTPS:     true,
				DNSAcrossProxy:     false,
				SsrPath:            "",
				BlackIcon:          false,
			}
			return pa, SettingEnCodeJSON(pa)
		}
		return &Setting{}, err
	}
	defer file.Close()
	pa := &Setting{}
	err = jsonpb.Unmarshal(file, pa)
	if err != nil {
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
