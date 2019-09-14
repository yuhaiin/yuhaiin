package configjson

import (
	"encoding/json"
	"os"
)

// Setting setting json struct
type Setting struct {
	PythonPath                     string `json:"pythonPath"`
	SsrPath                        string `json:"ssrPath"`
	PidFile                        string `json:"pidPath"`
	LogFile                        string `json:"logPath"`
	FastOpen                       bool   `json:"fastOpen"`
	Works                          string `json:"works"`
	LocalAddress                   string `json:"localAddress"`
	LocalPort                      string `json:"localPort"`
	TimeOut                        string `json:"timeOut"`
	HttpProxy                      bool   `json:"httpProxy"`
	HttpWithBypass                 bool   `json:"httpWithBypass"`
	HttpProxyAddressAndPort        string `json:"httpProxyAddressAndPort"`
	Socks5WithBypassAddressAndPort string `json:"socks5WithBypassAddressAndPort"`
	BypassFile                     string `json:"bypassFile"`
	BypassDomainFile               string `json:"bypassDomainFile"`
	DirectProxyFile                string `json:"directProxyFile"`
	Socks5WithBypass               bool   `json:"socks5WithBypass"`
	DnsServer                      string `json:"dnsServer"`
	UdpTrans                       bool   `json:"udpTrans"`
}

// SettingInitJSON init setting json file
func SettingInitJSON(configPath string) error {
	pa := &Setting{
		PythonPath:                     GetPythonPath(),
		SsrPath:                        configPath + "/shadowsocksr/shadowsocks/local.py",
		PidFile:                        configPath + "/shadowsocksr.pid",
		LogFile:                        "",
		FastOpen:                       true,
		Works:                          "8",
		LocalAddress:                   "127.0.0.1",
		LocalPort:                      "1080",
		TimeOut:                        "1000",
		HttpProxy:                      true,
		HttpWithBypass:                 true,
		HttpProxyAddressAndPort:        "127.0.0.1:8188",
		Socks5WithBypassAddressAndPort: "127.0.0.1:1083",
		BypassFile:                     configPath + "/cidrBypass.conf",
		BypassDomainFile:               configPath + "/domainBypass.conf",
		DirectProxyFile:                configPath + "/domainProxy.conf",
		Socks5WithBypass:               true,
		DnsServer:                      "119.29.29.29:53",
		UdpTrans:                       true,
	}
	if err := SettingEnCodeJSON(configPath, pa); err != nil {
		return err
	}
	return nil
}

// SettingDecodeJSON decode setting json to struct
func SettingDecodeJSON(configPath string) (*Setting, error) {
	pa := &Setting{}
	file, err := os.Open(configPath + "/SsrMicroConfig.json")
	if err != nil {
		return &Setting{}, err
	}
	if json.NewDecoder(file).Decode(&pa) != nil {
		return &Setting{}, err
	}
	return pa, nil
}

// SettingEnCodeJSON encode setting struct to json
func SettingEnCodeJSON(configPath string, pa *Setting) error {
	file, err := os.Create(configPath + "/SsrMicroConfig.json")
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
