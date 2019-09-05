// +build windows

package configjson

import (
	"bytes"
	"log"
	"os/exec"
	"strings"
)

//// GetConfig <-- like this
//func GetConfig(configPath string) map[string]string {
//	argument := make(map[string]string)
//	argument["pidFile"] = configPath + `\shadowsocksr.pid`
//	argument["logFile"] = os.DevNull
//	argument["pythonPath"] = GetPythonPath()
//	argument["ssrPath"] = configPath + `\shadowsocksr\shadowsocks\local.py`
//	argument["httpProxy"] = "127.0.0.1:8188"
//	argument["dnsServer"] = "119.29.29.29:53"
//
//	argument["localAddress"] = "127.0.0.1"
//	argument["localPort"] = "1080"
//
//	configTemp, err := ioutil.ReadFile(configPath + `\ssr_config.conf`)
//	if err != nil {
//		fmt.Println(err)
//	}
//
//	re, _ := regexp.Compile("#.*$")
//	for _, configTemp2 := range strings.Split(string(configTemp), "\r\n") {
//		configTemp2 := strings.Split(re.ReplaceAllString(configTemp2, ""), " ")
//		argumentMatch(argument, configTemp2)
//	}
//	return argument
//}

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
