package ssr_init

import (
	"fmt"
	"os"

	//"runtime"

	//"path/filepath"
	//"database/sql"

	"path/filepath"

	SsrDownload "../shadowsocksr"
	"../subscription"
)

// Path_exists 判断目录是否存在返回布尔类型
func Path_exists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsExist(err) {
			return true
		} else {
			return false
		}
	} else {
		return true
	}
}

// Init  <-- init
func Init(configPath, sqlPath string) {
	//判断目录是否存在 不存在则创建
	if !Path_exists(configPath) {
		err := os.MkdirAll(configPath, os.ModePerm)
		if err != nil {
			fmt.Println(err)
		}
	}

	if !Path_exists(sqlPath) {
		go subscription.Subscription_link_init(sqlPath)
		go subscription.Init_config_db(sqlPath)
		go subscription.Ssr_server_node_init(sqlPath)
		// Auto_create_config(config_path)
	}

	if !Path_exists(configPath + "/ssr_config.conf") {
		autoCreateConfig(configPath)
	}

	if !Path_exists(configPath + "/shadowsocksr") {
		SsrDownload.Get_ssr_python(configPath)
	}
}

// MenuInit <-- will no use
func MenuInit(path string) {
	// //获取当前可执行文件目录
	// file, _ := exec.LookPath(os.Args[0])
	// path2, _ := filepath.Abs(file)
	// rst := filepath.Dir(path2)
	rst, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	//fmt.Println(rst)

	fmt.Println("当前配置文件目录:" + path)
	fmt.Println("当前可执行文件目录:" + rst)
}
