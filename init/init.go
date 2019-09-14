package ssrinit

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"../config/configjson"
	SsrDownload "../shadowsocksr"
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

	// if !PathExists(sqlPath) {
	// 	subscription.LinkInit(sqlPath)
	// 	subscription.NodeInit(sqlPath)
	// 	subscription.NowNodeInit(sqlPath)
	// 	// Auto_create_config(config_path)
	// }

	//if !PathExists(configPath + "/ssr_config.conf") {
	//	autoCreateConfig(configPath)
	//}

	if !PathExists(configPath + "/shadowsocksr") {
		SsrDownload.GetSsrPython(configPath)
	}

	if !PathExists(configPath + "/node.json") {
		if configjson.InitJSON(configPath) != nil {
			return
		}
	}

	if !PathExists(configPath + "/SsrMicroConfig.json") {
		if configjson.SettingInitJSON(configPath) != nil {
			return
		}
	}

	if !PathExists(configPath + "/cidrBypass.conf") {
		res, err := http.Get("https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/ACL/ssrMicroClientBypass.conf")
		if err != nil {
			panic(err)
		}
		f, err := os.Create(configPath + "/cidrBypass.conf")
		if err != nil {
			panic(err)
		}
		io.Copy(f, res.Body)
	}

	if !PathExists(configPath + "/domainBypass.conf") {
		res, err := http.Get("https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/ACL/ssrMicroClientDomainBypass.conf")
		if err != nil {
			panic(err)
		}
		f, err := os.Create(configPath + "/domainBypass.conf")
		if err != nil {
			panic(err)
		}
		io.Copy(f, res.Body)
	}

	if !PathExists(configPath + "/domainProxy.conf") {
		//res, err := http.Get("https://raw.githubusercontent.com/Asutorufa/SsrMicroClient/ACL/ssrMicroClientBypass.conf")
		//if err != nil {
		//	panic(err)
		//}
		_, err := os.Create(configPath + "/domainProxy.conf")
		if err != nil {
			panic(err)
		}
		//io.Copy(f, res.Body)
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
		io.Copy(f, res.Body)
	}
}

/*
// MenuInit <-- will no use
func MenuInit(path string) {
	// //获取当前可执行文件目录
	// file, _ := exec.LookPath(os.Args[0])
	// path2, _ := filepath.Abs(file)
	// rst := filepath.Dir(path2)
	// rst, _ := filepath.Abs(filepath.Dir(os.Args[0]))

}
*/
