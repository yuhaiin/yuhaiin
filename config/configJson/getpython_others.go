// +build !windows

package configjson

import (
	"bytes"
	"os/exec"
	"strings"
)

//// GetConfig <-- like this
//func GetConfig(configPath string) map[string]string {
//	argument := map[string]string{}
//	argument["pidFile"] = configPath + "/shadowsocksr.pid"
//	argument["cidrFile"] = configPath + "/cidrBypass.conf"
//	argument["logFile"] = os.DevNull
//	argument["pythonPath"] = GetPythonPath()
//	argument["httpProxy"] = "127.0.0.1:8188"
//	argument["dnsServer"] = "119.29.29.29:53"
//
//	// if argument["Workers"] == "" {
//	// 	argument["Workers"] = "--workers " + "1 "
//	// }
//
//	argument["ssrPath"] = configPath + "/shadowsocksr/shadowsocks/local.py"
//	argument["localAddress"] = "127.0.0.1"
//	argument["localPort"] = "1080"
//
//	configTemp, err := ioutil.ReadFile(configPath + "/ssr_config.conf")
//	if err != nil {
//		fmt.Println(err)
//	}
//
//	re, _ := regexp.Compile("#.*$")
//	for _, configTemp2 := range strings.Split(string(configTemp), "\n") {
//		configTemp2 := strings.Split(re.ReplaceAllString(configTemp2, ""), " ")
//		argumentMatch(argument, configTemp2)
//	}
//	return argument
//}

// GetPythonPath get python path
func GetPythonPath() string {
	var out bytes.Buffer
	cmd := exec.Command("sh", "-c", "which python3")
	cmd.Stdin = strings.NewReader("some input")
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		cmd = exec.Command("sh", "-c", "which python")
		cmd.Stdout = &out
		err = cmd.Run()
		if err != nil {
			return ""
		}
	}
	return strings.Replace(out.String(), "\n", "", -1)
}
