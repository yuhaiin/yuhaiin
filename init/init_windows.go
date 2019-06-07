// +build windows

package ssr_init

import (
	"fmt"
	"io/ioutil"
	"os"

	"../config"
)

func autoCreateConfig(configPath string) {
	inLine := "\r\n"
	fastOpen := "fast-open" + inLine
	workers := "workers 8" + inLine
	localAddress := "#local_address 127.0.0.1" + inLine
	localPort := "#local_port 1080" + inLine
	connectVerboseInfo := "#connect-verbose-info" + inLine
	timeOut := "#timeout 1000" + inLine
	acl := ""
	pythonPath := "#python_path " + config.GetPythonPath() + "#python路径" + inLine
	deamon := "#deamon" + inLine
	configFile := configPath + `\ssr_config.conf`
	ssrPath := "#ssr_path" + configPath + "\\shadowsocksr\\shadowsocks\\local.py #ssr路径" + inLine
	pidFile := ""
	logFile := ""

	configConf := pythonPath + ssrPath + pidFile + logFile + fastOpen + deamon + timeOut + workers + localAddress + localPort + connectVerboseInfo + acl
	fmt.Println(configConf)
	ioutil.WriteFile(configFile, []byte(configConf), 0644)
}

// GetConfigAndSQLPath <-- get the config path
func GetConfigAndSQLPath() (configPath string, sqlPath string) {
	return os.Getenv("USERPROFILE") + "\\Documents\\SSRSub", os.Getenv("USERPROFILE") + "\\Documents\\SSRSub" + "\\SSR_config.db"
}
