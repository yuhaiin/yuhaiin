package ssrcontrol

import (
	"SsrMicroClient/config"
	"SsrMicroClient/subscription"
	"log"
	"os"
	"os/exec"
	"strings"
)

// GetConfigArgument <-- like this
func GetConfigArgument() map[string]string {
	return map[string]string{
		"server":     "-s",
		"serverPort": "-p",
		"protocol":   "-O",
		"method":     "-m",
		"obfs":       "-o",
		"password":   "-k",
		"obfsparam":  "-g",
		"protoparam": "-G",
		"pidFile":    "--pid-file",
		//"logFile":            "--log-file",
		"localAddress": "-b",
		"localPort":    "-l",
		//"connectVerboseInfo": "--connect-verbose-info",
		"workers":  "--workers",
		"fastOpen": "--fast-open",
		"acl":      "--acl",
		"timeout":  "-t",
		"udpTrans": "-u",
	}
}

// GetConfig convert config to map
func GetConfig(configPath string) map[string]string {
	argument := map[string]string{}
	settingDecodeJSON, err := config.SettingDecodeJSON(configPath)
	if err != nil {
		log.Println(err)
		return argument
	}
	argument["pidFile"] = settingDecodeJSON.PidFile
	argument["logFile"] = os.DevNull
	argument["httpProxy"] = settingDecodeJSON.HttpProxyAddressAndPort
	argument["dnsServer"] = settingDecodeJSON.DnsServer
	argument["ssrPath"] = settingDecodeJSON.SsrPath
	argument["localAddress"] = settingDecodeJSON.LocalAddress
	argument["localPort"] = settingDecodeJSON.LocalPort
	argument["socks5WithBypassAddressAndPort"] = settingDecodeJSON.Socks5WithBypassAddressAndPort
	argument["bypassFile"] = settingDecodeJSON.BypassFile

	//argument["cidrFile"] = settingDecodeJSON.BypassFile
	//argument["bypassDomainFile"] = settingDecodeJSON.BypassDomainFile
	//argument["directProxyFile"] = settingDecodeJSON.DirectProxyFile
	//argument["discordDomainFile"] = settingDecodeJSON.DiscordDomainFile
	//argument["pythonPath"] = settingDecodeJSON.PythonPath
	// if argument["Workers"] == "" {
	// 	argument["Workers"] = "--workers " + "1 "
	// }
	if settingDecodeJSON.UdpTrans == true {
		argument["udpTrans"] = "true"
	}
	if settingDecodeJSON.FastOpen == true {
		argument["fastOpen"] = "true"
	}

	return argument
}

// GetSsrCmd <--
func GetSsrCmd(configPath string) *exec.Cmd {
	argument := GetConfigArgument()
	nodeAndConfig, _ := subscription.GetNowNode(configPath)
	for key, value := range GetConfig(configPath) {
		nodeAndConfig[key] = value
	}
	// now not use
	// logFile , PidFile
	nodeAndConfigArgument := []string{"server", "serverPort", "protocol", "method",
		"obfs", "password", "obfsparam", "protoparam", "localAddress",
		"localPort", "timeout"}
	// argumentArgument := []string{"localAddress", "localPort", "logFile", "pidFile", "workers", "acl", "timeout"}
	argumentSingle := []string{"fastOpen", "udpTrans"}

	var cmdArray []string
	cmdArray = []string{}
	if nodeAndConfig["ssrPath"] != "" {
		cmdArray = append(cmdArray, strings.Split(nodeAndConfig["ssrPath"], " ")...)
	}
	for _, nodeA := range nodeAndConfigArgument {
		if nodeAndConfig[nodeA] != "" {
			cmdArray = append(cmdArray, argument[nodeA], nodeAndConfig[nodeA])
		}
	}
	/*
		for _, argumentA := range argumentArgument {
			if config[argumentA] != "" {
				cmdArray = append(cmdArray, argument[argumentA], config[argumentA])
			}
		}
	*/

	for _, argumentS := range argumentSingle {
		if nodeAndConfig[argumentS] != "" {
			cmdArray = append(cmdArray, argument[argumentS])
		}
	}

	cmd := exec.Command(cmdArray[0], cmdArray[1:]...)
	log.Println(nodeAndConfig["pythonPath"], cmdArray)
	return cmd
}
