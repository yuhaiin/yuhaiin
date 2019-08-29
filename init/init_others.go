// +build !windows

package init

import (
	"os"
)

//func autoCreateConfig(configPath string) {
//	inLine := "\n"
//	// deamon := "deamon" + inLine
//	configFile := configPath + "/ssr_config.conf"
//	ssrPath := "#ssr_path" + configPath + "/shadowsocksr/shadowsocks/local.py #ssr路径" + inLine
//	pidFile := "pid-file " + configPath + "/shadowsocksr.pid" + inLine
//	logFile := "log-file " + os.DevNull + inLine
//	fastOpen := "fast-open" + inLine
//	workers := "workers 8" + inLine
//	localAddress := "#local_address 127.0.0.1" + inLine
//	localPort := "#local_port 1080" + inLine
//	connectVerboseInfo := "#connect-verbose-info" + inLine
//	timeOut := "#timeout 1000" + inLine
//	acl := ""
//	pythonPath := "#python_path " + config.GetPythonPath() + "#python路径" + inLine
//	httpProxy := "#httpProxy 127.0.0.1:8188"
//
//	configConf := pythonPath + ssrPath + pidFile + logFile + fastOpen + timeOut + workers + localAddress + localPort + connectVerboseInfo + acl + httpProxy
//	fmt.Println(configConf)
//	_ = ioutil.WriteFile(configFile, []byte(configConf), 0644)
//}

// GetConfigAndSQLPath <-- get the config path
func GetConfigAndSQLPath() (configPath string) {
	return os.Getenv("HOME") + "/.config/SSRSub"
}
