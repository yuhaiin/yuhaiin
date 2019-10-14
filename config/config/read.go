package config

import (
	"SsrMicroClient/config/configjson"
	"log"
	"os"
)

// GetConfig convert config to map
func GetConfig(configPath string) map[string]string {
	argument := map[string]string{}
	settingDecodeJSON, err := configjson.SettingDecodeJSON(configPath)
	if err != nil {
		log.Println(err)
		return argument
	}
	argument["pidFile"] = settingDecodeJSON.PidFile
	argument["cidrFile"] = settingDecodeJSON.BypassFile
	argument["bypassDomainFile"] = settingDecodeJSON.BypassDomainFile
	argument["directProxyFile"] = settingDecodeJSON.DirectProxyFile
	argument["discordDomainFile"] = settingDecodeJSON.DiscordDomainFile
	argument["logFile"] = os.DevNull
	argument["pythonPath"] = settingDecodeJSON.PythonPath
	argument["httpProxy"] = settingDecodeJSON.HttpProxyAddressAndPort
	argument["dnsServer"] = settingDecodeJSON.DnsServer

	// if argument["Workers"] == "" {
	// 	argument["Workers"] = "--workers " + "1 "
	// }
	argument["ssrPath"] = settingDecodeJSON.SsrPath
	argument["localAddress"] = settingDecodeJSON.LocalAddress
	argument["localPort"] = settingDecodeJSON.LocalPort
	argument["socks5WithBypassAddressAndPort"] = settingDecodeJSON.Socks5WithBypassAddressAndPort
	if settingDecodeJSON.UdpTrans == true {
		argument["udpTrans"] = "true"
	}
	if settingDecodeJSON.FastOpen == true {
		argument["fastOpen"] = "true"
	}

	return argument
}
