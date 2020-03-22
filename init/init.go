package ssrinit

import (
	"fmt"
	"github.com/Asutorufa/SsrMicroClient/config"
	"github.com/Asutorufa/SsrMicroClient/subscr"
	"io"
	"net/http"
	"os"
)

// PathExists 判断目录是否存在返回布尔类型
func PathExists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

// Init  <-- init
func Init(configPath string) {
	//判断目录是否存在 不存在则创建
	if !PathExists(configPath) {
		err := os.MkdirAll(configPath, os.ModePerm)
		if err != nil {
			fmt.Println(err)
		}
	}

	if !PathExists(configPath + "/shadowsocksr") {
		GetSsrPython(configPath)
	}

	//cycle import,not allow
	if !PathExists(configPath + "/node.json") {
		if subscr.InitJSON(configPath) != nil {
			return
		}
	}

	if !PathExists(configPath + "/SsrMicroConfig.json") {
		if config.SettingInitJSON(configPath) != nil {
			return
		}
	}

	if !PathExists(configPath + "/SsrMicroClient.conf") {
		res, err := http.Get("https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/ACL/SsrMicroClient/SsrMicroClient.conf")
		if err != nil {
			panic(err)
		}
		f, err := os.Create(configPath + "/SsrMicroClient.conf")
		if err != nil {
			panic(err)
		}
		_, _ = io.Copy(f, res.Body)
	}

	if !PathExists(configPath + "/SsrMicroClient.png") {
		res, err := http.Get("https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/master/SsrMicroClient.png")
		if err != nil {
			panic(err)
		}
		f, err := os.Create(configPath + "/SsrMicroClient.png")
		if err != nil {
			panic(err)
		}
		_, _ = io.Copy(f, res.Body)
	}
}
