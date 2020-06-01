package process

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/subscr"
)

// PathExists 判断目录是否存在返回布尔类型
func PathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	return os.IsExist(err)
}

func init() {
	//判断目录是否存在 不存在则创建
	if !PathExists(config.Path) {
		err := os.MkdirAll(config.Path, os.ModePerm)
		if err != nil {
			fmt.Println(err)
		}
	}

	//cycle import,not allow
	if !PathExists(config.Path + "/node.json") {
		if subscr.InitJSON() != nil {
			return
		}
	}

	if !PathExists(config.ConPath) {
		if config.SettingInitJSON() != nil {
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

	//if !PathExists(config.Path + "/shadowsocksr") {
	//	GetSsrPython(config.Path)
	//}
}

func processInit() {
	controlInit()
	proxyInit()
	matchInit()
}
