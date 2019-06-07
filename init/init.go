package ssr_init

import (
	"fmt"
	"os"
	"runtime"

	//"runtime"
	"sync"
	//"path/filepath"
	//"database/sql"
	"io/ioutil"

	"path/filepath"

	"../config"
	SsrDownload "../shadowsocksr"
	"../subscription"
)

//判断目录是否存在返回布尔类型
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

func Init(config_path, sql_db_path string) {
	//判断目录是否存在 不存在则创建
	if !Path_exists(config_path) {
		err := os.MkdirAll(config_path, os.ModePerm)
		if err != nil {
			fmt.Println(err)
		}
	}

	if !Path_exists(sql_db_path) {
		var wg sync.WaitGroup

		wg.Add(1)
		go subscription.Subscription_link_init(sql_db_path, &wg)
		wg.Add(1)
		go subscription.Init_config_db(sql_db_path, &wg)
		wg.Add(1)
		go subscription.Ssr_server_node_init(sql_db_path, &wg)
		// Auto_create_config(config_path)

		wg.Wait()
	}

	if !Path_exists(config_path + "/ssr_config.conf") {
		autoCreateConfig(config_path)
	}

	if !Path_exists(config_path + "/shadowsocksr") {
		SsrDownload.Get_ssr_python(config_path)
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

func autoCreateConfig(configPath string) {
	inLine := "\n"
	if runtime.GOOS == "windows" {
		inLine = "\r\n"
	}

	deamon := "deamon" + inLine
	configFile := configPath + "/ssr_config.conf"
	ssrPath := "#ssr_path" + configPath + "/shadowsocksr/shadowsocks/local.py #ssr路径" + inLine
	pidFile := "pid-file " + configPath + "/shadowsocksr.pid" + inLine
	logFile := "log-file /dev/null" + inLine
	fastOpen := "fast-open" + inLine
	workers := "workers 8" + inLine
	localAddress := "#local_address 127.0.0.1" + inLine
	localPort := "#local_port 1080" + inLine
	connectVerboseInfo := "#connect-verbose-info" + inLine
	timeOut := "#timeout 1000" + inLine
	acl := ""
	pythonPath := "#python_path " + config.Get_python_path() + "#python路径" + inLine

	if runtime.GOOS == "windows" {
		deamon = "#deamon" + inLine
		configFile = configPath + `\ssr_config.conf`
		ssrPath = "#ssr_path" + configPath + "\\shadowsocksr\\shadowsocks\\local.py #ssr路径" + inLine
		pidFile = ""
		logFile = ""
	}

	configConf := pythonPath + ssrPath + pidFile + logFile + fastOpen + deamon + timeOut + workers + localAddress + localPort + connectVerboseInfo + acl
	fmt.Println(configConf)
	ioutil.WriteFile(configFile, []byte(configConf), 0644)
}
