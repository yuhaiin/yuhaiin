package config

import (
	"os"
	"strings"
)

// GetConfigArgument <-- like this
func GetConfigArgument() map[string]string {
	return map[string]string{
		"server":     "-s",
		"serverPort": "-p",
		"protocol":   "-O",
		"method":     "-m",
		"obfs":       "-o",
		"password":   "-k",
		"obfsparam":  "-g",
		"protoparam": "-G",
		"pidFile":    "--pid-file",
		//"logFile":            "--log-file",
		"localAddress": "-b",
		"localPort":    "-l",
		//"connectVerboseInfo": "--connect-verbose-info",
		"workers":  "--workers",
		"fastOpen": "--fast-open",
		"acl":      "--acl",
		"timeout":  "-t",
		"udpTrans": "-u",
	}
}

// GetFunctionString like name
func GetFunctionString() map[string]string {
	SystemLanguage := strings.Split(os.Getenv("LANGUAGE"), "_")[0]
	if SystemLanguage == "zh" {
		return map[string]string{
			"menu":           "1.开启ssr\n2.更换节点/查看所有节点\n3.更新所有订阅\n4.添加订阅链接\n5.删除订阅链接\n6.获取延迟\n7.结束ssr后台\n8.结束此程序(ssr后台运行)\n9.开启http代理(9b.开启分流)\n>>> ",
			"nowNode":        "当前节点: ",
			"configPath":     "配置文件目录: ",
			"executablePath": "可执行文件目录: ",
			"enterError":     "输入错误!",
			"returnMenu":     "输入0返回菜单",
		}
	}
	return map[string]string{
		"menu":           "1.start shadowsocksr\n2.change now node/watch all node\n3.update all subscriptions\n4.add subscription's link\n5.delete one subscription's link\n6.get one node delay\n7.shut down shadowsocksr daemon\n8.close this function(shadowsocksr running daemon)\n9.start HTTP proxy(9b.bypass)\n>>> ",
		"nowNode":        "now node: ",
		"configPath":     "config path: ",
		"executablePath": "executable file path: ",
		"enterError":     "enter error!",
		"returnMenu":     "enter 0 return to menu",
	}
}
