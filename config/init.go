package config

import (
	"io"
	"net/http"
	"os"
)

// PathExists 判断目录是否存在返回布尔类型
func PathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	return os.IsExist(err)
}

func PathInit() (err error) {
	//判断目录是否存在 不存在则创建
	if !PathExists(Path) {
		err := os.MkdirAll(Path, os.ModePerm)
		if err != nil {
			return err
		}
	}

	//cycle import,not allow
	//if !PathExists(Path + "/node.json") {
	//	if err = subscr.InitJSON(); err != nil {
	//		return
	//	}
	//}

	if !PathExists(ConPath) {
		if err = SettingInitJSON(); err != nil {
			return
		}
	}

	if !PathExists(Path + "/yuhaiin.conf") {
		res, err := http.Get("https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/ACL/yuhaiin/yuhaiin.conf")
		if err != nil {
			return err
		}
		f, err := os.Create(Path + "/yuhaiin.conf")
		if err != nil {
			return err
		}
		_, _ = io.Copy(f, res.Body)
	}
	return nil
	//if !PathExists(config.Path + "/shadowsocksr") {
	//	GetSsrPython(config.Path)
	//}
}
