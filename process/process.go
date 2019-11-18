package process

import (
	"os/exec"

	"SsrMicroClient/config/config"
	"SsrMicroClient/config/configjson"
	"SsrMicroClient/microlog"
)

// GetSsrCmd <--
func GetSsrCmd(configPath string) *exec.Cmd {
	argument := config.GetConfigArgument()
	nodeAndConfig, _ := configjson.GetNowNode(configPath)
	for key, value := range config.GetConfig(configPath) {
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
	if nodeAndConfig["ssrPath"] != "" {
		cmdArray = append(cmdArray, nodeAndConfig["ssrPath"])
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
	cmd := exec.Command(nodeAndConfig["pythonPath"], cmdArray...)
	microlog.Debug(nodeAndConfig["pythonPath"], cmdArray)
	return cmd
}
