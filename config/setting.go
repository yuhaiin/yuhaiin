package config

import (
	"encoding/json"
	"os"
	"os/user"
)

var (
	usr, _        = user.Current()
	pathSeparator = string(os.PathSeparator)
	ConPath       = Path + pathSeparator + "yuhaiinConfig.json"
)

//Setting setting json struct
type settingI struct {
	BlackIcon          bool   `json:"black_icon"`
	IsDNSOverHTTPS     bool   `json:"is_dns_over_https"`
	DNSAcrossProxy     bool   `json:"dns_across_proxy"`
	DnsServer          string `json:"dnsServer"`
	DnsSubNet          string `json:"dns_sub_net"`
	Bypass             bool   `json:"bypass"`
	HttpProxyAddress   string `json:"httpProxyAddress"`
	Socks5ProxyAddress string `json:"socks5ProxyAddress"`
	RedirProxyAddress  string `json:"redir_proxy_address"`
	BypassFile         string `json:"bypassFile"`
	SsrPath            string `json:"ssrPath"`
	LocalAddress       string `json:"localAddress"`
	LocalPort          string `json:"localPort"`

	// not use now
	PythonPath   string `json:"pythonPath"`
	PidFile      string `json:"pidPath"`
	LogFile      string `json:"logPath"`
	FastOpen     bool   `json:"fastOpen"`
	Works        string `json:"works"`
	TimeOut      string `json:"timeOut"`
	HttpProxy    bool   `json:"httpProxy"`
	UdpTrans     bool   `json:"udpTrans"`
	AutoStartSsr bool   `json:"autoStartSsr"`
	IsPrintLog   bool   `json:"is_print_log"`
	UseLocalDNS  bool   `json:"use_local_dns"`
}

// SettingInitJSON init setting json file
func SettingInitJSON() error {
	pa := &settingI{
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

		//not use now
		HttpProxy:    true,
		AutoStartSsr: true,
		IsPrintLog:   false,
		PythonPath:   "",
		LocalAddress: "0.0.0.0",
		LocalPort:    "0",
		TimeOut:      "1000",
		UseLocalDNS:  false,
		UdpTrans:     true,
		PidFile:      "",
		LogFile:      "",
		FastOpen:     true,
		Works:        "8",
	}
	if err := SettingEnCodeJSON(reTrans(pa)); err != nil {
		return err
	}
	return nil
}

// SettingDecodeJSON decode setting json to struct
func SettingDecodeJSON() (*Setting, error) {
	pa := &settingI{}
	file, err := os.Open(ConPath)
	if err != nil {
		return &Setting{}, err
	}
	if json.NewDecoder(file).Decode(&pa) != nil {
		return &Setting{}, err
	}

	return reTrans(pa), nil
}

func trans(i *Setting) *settingI {
	return iTrans(i).(*settingI)
}

func reTrans(i *settingI) *Setting {
	return iTrans(i).(*Setting)
}

func iTrans(ii interface{}) interface{} {
	switch ii.(type) {
	case *settingI:
		x := &Setting{}
		i := ii.(*settingI)
		x.BlackIcon = i.BlackIcon
		x.SsrPath = i.SsrPath
		x.RedirProxyAddress = i.RedirProxyAddress
		x.Socks5ProxyAddress = i.Socks5ProxyAddress
		x.HttpProxyAddress = i.HttpProxyAddress
		x.Bypass = i.Bypass
		x.BypassFile = i.BypassFile
		x.DnsServer = i.DnsServer
		x.DnsSubNet = i.DnsSubNet
		x.DNSAcrossProxy = i.DNSAcrossProxy
		x.IsDNSOverHTTPS = i.IsDNSOverHTTPS
		return x
	case *Setting:
		x := &settingI{}
		i := ii.(*Setting)
		x.BlackIcon = i.BlackIcon
		x.SsrPath = i.SsrPath
		x.RedirProxyAddress = i.RedirProxyAddress
		x.Socks5ProxyAddress = i.Socks5ProxyAddress
		x.HttpProxyAddress = i.HttpProxyAddress
		x.Bypass = i.Bypass
		x.BypassFile = i.BypassFile
		x.DnsServer = i.DnsServer
		x.DnsSubNet = i.DnsSubNet
		x.DNSAcrossProxy = i.DNSAcrossProxy
		x.IsDNSOverHTTPS = i.IsDNSOverHTTPS
		return x
	}
	return nil
}

// SettingEnCodeJSON encode setting struct to json
func SettingEnCodeJSON(pa *Setting) error {
	file, err := os.Create(ConPath)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(file)
	enc.SetIndent("", "    ")
	if err := enc.Encode(trans(pa)); err != nil {
		return err
	}
	return nil
}
