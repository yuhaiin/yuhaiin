package ssrinit

import (
	"fmt"
	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/subscr"
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
func Init() {
	//判断目录是否存在 不存在则创建
	if !PathExists(config.Path) {
		err := os.MkdirAll(config.Path, os.ModePerm)
		if err != nil {
			fmt.Println(err)
		}
	}

	if !PathExists(config.Path + "/shadowsocksr") {
		GetSsrPython(config.Path)
	}

	//cycle import,not allow
	if !PathExists(config.Path + "/node.json") {
		if subscr.InitJSON() != nil {
			return
		}
	}

	if !PathExists(config.Path) {
		if config.SettingInitJSON(config.Path) != nil {
			return
		}
	}

	if !PathExists(config.Path + "/yuhaiin.conf") {
		res, err := http.Get("https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/ACL/yuhaiin/yuhaiin.conf")
		if err != nil {
			panic(err)
		}
		f, err := os.Create(config.Path + "/yuhaiin.conf")
		if err != nil {
			panic(err)
		}
		_, _ = io.Copy(f, res.Body)
	}
}
