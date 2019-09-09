package process

import (
	"io/ioutil"
	"os/exec"
	"strconv"

	"../config/config"
	"../config/configjson"
	"../microlog"
)

// Start start ssr
func Start(configPath string) {
	// pid, status := Get(configPath)
	// if status == true {
	// 	log.Println("already have run at " + pid)
	// 	return
	// }
	argument := config.GetConfigArgument()
	// nodeAndConfig, _ := subscription.GetNowNodeAll(sqlPath)
	nodeAndConfig, _ := configjson.GetNowNode(configPath)
	for v, config := range config.GetConfig(configPath) {
		nodeAndConfig[v] = config
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
		}*/

	for _, argumentS := range argumentSingle {
		if nodeAndConfig[argumentS] != "" {
			cmdArray = append(cmdArray, argument[argumentS])
		}
	}
	// log.Println(cmdArray)
	// if runtime.GOOS != "windows" {
	// 	cmdArray = append(cmdArray, "-d", "start")
	// }
	// fmt.Println(cmdArray)
	cmd := exec.Command(nodeAndConfig["pythonPath"], cmdArray...)
	microlog.Debug(nodeAndConfig["pythonPath"], cmdArray)
	_ = cmd.Start()
	// cmd.Process.Release()
	// cmd.Process.Signal(syscall.SIGUSR1)
	// fmt.Println(cmd.Process.Pid, config["pidFile"])
	_ = ioutil.WriteFile(nodeAndConfig["pidFile"], []byte(strconv.Itoa(cmd.Process.Pid)), 0644)
}
