package config

import (
	"encoding/json"
	"os"
)

var (
	configPath = Path + "/yuhaiinConfig.json"
)

// Setting setting json struct
type Setting struct {
	PythonPath         string `json:"pythonPath"`
	SsrPath            string `json:"ssrPath"`
	PidFile            string `json:"pidPath"`
	LogFile            string `json:"logPath"`
	FastOpen           bool   `json:"fastOpen"`
	Works              string `json:"works"`
	LocalAddress       string `json:"localAddress"`
	LocalPort          string `json:"localPort"`
	TimeOut            string `json:"timeOut"`
	HttpProxy          bool   `json:"httpProxy"`
	Bypass             bool   `json:"bypass"`
	HttpProxyAddress   string `json:"httpProxyAddress"`
	Socks5ProxyAddress string `json:"socks5ProxyAddress"`
	RedirProxyAddress  string `json:"redir_proxy_address"`
	BypassFile         string `json:"bypassFile"`
	DnsServer          string `json:"dnsServer"`
	UdpTrans           bool   `json:"udpTrans"`
	AutoStartSsr       bool   `json:"autoStartSsr"`
	IsPrintLog         bool   `json:"is_print_log"`
	IsDNSOverHTTPS     bool   `json:"is_dns_over_https"`
	DNSAcrossProxy     bool   `json:"dns_across_proxy"`
	UseLocalDNS        bool   `json:"use_local_dns"`
}

// SettingInitJSON init setting json file
func SettingInitJSON(configPath string) error {
	pa := &Setting{
		AutoStartSsr:       true,
		PythonPath:         GetPythonPath(),
		SsrPath:            GetPythonPath() + " " + configPath + "/shadowsocksr/shadowsocks/local.py",
		LocalAddress:       "127.0.0.1",
		LocalPort:          "1083",
		Bypass:             true,
		HttpProxy:          true,
		HttpProxyAddress:   "127.0.0.1:8188",
		Socks5ProxyAddress: "127.0.0.1:1080",
		RedirProxyAddress:  "127.0.0.1:8088",
		IsPrintLog:         false,

		TimeOut:        "1000",
		BypassFile:     configPath + "/yuhaiin.conf",
		IsDNSOverHTTPS: false,
		DnsServer:      "1.0.0.1:53",
		DNSAcrossProxy: false,
		UseLocalDNS:    false,
		UdpTrans:       true,
		PidFile:        configPath + "/shadowsocksr.pid",
		LogFile:        "",
		FastOpen:       true,
		Works:          "8",
	}
	if err := SettingEnCodeJSON(pa); err != nil {
		return err
	}
	return nil
}

// SettingDecodeJSON decode setting json to struct
func SettingDecodeJSON() (*Setting, error) {
	pa := &Setting{}
	file, err := os.Open(configPath)
	if err != nil {
		return &Setting{}, err
	}
	if json.NewDecoder(file).Decode(&pa) != nil {
		return &Setting{}, err
	}
	return pa, nil
}

// SettingEnCodeJSON encode setting struct to json
func SettingEnCodeJSON(pa *Setting) error {
	file, err := os.Create(configPath)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(file)
	enc.SetIndent("", "    ")
	if err := enc.Encode(&pa); err != nil {
		return err
	}
	return nil
}
