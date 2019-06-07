// +build windows

package config

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"regexp"
	"strings"
)

// GetConfig <-- like this
func GetConfig(configPath string) map[string]string {
	argument := map[string]string{}
	argument["pidFile"] = configPath + "/shadowsocksr.pid"
	argument["logFile"] = "/dev/null"
	argument["pythonPath"] = GetPythonPath()
	inLine := "\r\n"
	argument["ssrPath"] = configPath + `\shadowsocksr\shadowsocks/local.py`

	argument["localAddress"] = "127.0.0.1"
	argument["localPort"] = "1080"

	configTemp, err := ioutil.ReadFile(configPath + "/ssr_config.conf")
	if err != nil {
		fmt.Println(err)
	}

	re, _ := regexp.Compile("#.*$")
	for _, configTemp2 := range strings.Split(string(configTemp), inLine) {
		configTemp2 := strings.Split(re.ReplaceAllString(configTemp2, ""), " ")
		switch configTemp2[0] {
		case "python_path":
			argument["pythonPath"] = configTemp2[1]
		case "-python_path":
			argument["pythonPath"] = ""
		case "ssr_path":
			argument["ssrPath"] = configTemp2[1]
		case "-ssr_path":
			argument["ssrPath"] = ""
		case "config_path":
			argument["configPath"] = configTemp2[1]
		case "connect-verbose-info":
			argument["connectVerboseInfo"] = "--connect-verbose-info"
		case "workers":
			argument["workers"] = configTemp2[1]
		case "fast-open":
			argument["fastOpen"] = "fast-open"
		case "pid-file":
			argument["pidFile"] = configTemp2[1]
		case "-pid-file":
			argument["pidFile"] = ""
		case "log-file":
			argument["logFile"] = configTemp2[1]
		case "-log-file":
			argument["logFile"] = ""
		case "local_address":
			argument["localAddress"] = configTemp2[1]
		case "local_port":
			argument["localPort"] = configTemp2[1]
		case "acl":
			argument["acl"] = configTemp2[1]
		case "timeout":
			argument["timeout"] = configTemp2[1]
		case "deamon":
			argument["deamon"] = "-d start"
		}
	}
	return argument
}

// GetPythonPath get python path
func GetPythonPath() string {
	var out bytes.Buffer
	cmd := exec.Command("cmd", "/c", "where python")
	cmd.Stdin = strings.NewReader("some input")
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
		return ""
	}
	return strings.Replace(out.String(), "\r\n", "", -1)
}
