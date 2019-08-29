package init

import (
	"fmt"
	"os"

	"../config/configJson"
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
