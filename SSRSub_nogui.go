// +build noGui

package main

import (
	"SsrMicroClient/net/delay"
	"SsrMicroClient/net/test"
	"flag"
	"fmt"
	"log"
	"os"

	"SsrMicroClient/config/config"
	"SsrMicroClient/config/configjson"
	"SsrMicroClient/init"
	"SsrMicroClient/process"
	// _ "github.com/mattn/go-sqlite3"
)

func menu(configPath string) {
	languageString := config.GetFunctionString()
	//初始化
	ssrinit.Init(configPath)
	//获取当前配置文件路径和可执行文件路径
	executablePath, err := os.Executable()
	if err != nil {
		log.Println(err)
	}

	fmt.Println(languageString["configPath"] + configPath)
	fmt.Println(languageString["executablePath"] + executablePath)
	//获取当前节点
	nowNode, err := configjson.GetNowNode(configPath)
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Println(languageString["nowNode"], nowNode["remarks"])
	for {
		fmt.Print(languageString["menu"])

		var selectTemp string
		_, _ = fmt.Scanln(&selectTemp)

		switch selectTemp {
		case "1":
			// ssr_process.Start(path, db_path)
			process.StartByArgument(configPath, "ssr")
		case "2":
			_, exist := process.Get(configPath)
			// selectB := subscription.ChangeNowNode(sqlPath)
			_ = configjson.ChangeNowNode(configPath)
			if exist == true {
				process.Stop(configPath)
				// ssr_process.Start(path, db_path)
				process.StartByArgument(configPath, "ssr")
			}
			// } else {
			// 	subscription.Ssr_server_node_change(db_path)
			// }
		case "3":
			// subscription.DeleteAllNode(sqlPath)
			// subscription.AddAllNodeFromLink(sqlPath)
			if configjson.SsrJSON(configPath) != nil {
				return
			}

		case "4":
			fmt.Print(config.GetFunctionString()["returnMenu"] + ">>> ")
			// var linkTemp string
			// fmt.Scanln(&linkTemp)
			// if linkTemp != "0" && linkTemp != "" {
			// subscription.AddLink(linkTemp, sqlPath)
			_ = configjson.AddLinkJSON(configPath)
			// }
		case "5":
			// subscription.LinkDelete(sqlPath)
			_ = configjson.RemoveLinkJSON(configPath)
		case "6":
			//delay_test_temp := config.Read_config_file(path)
			//GetDelay.Get_delay(strings.Split(delay_test_temp["Local_address"], " ")[1], strings.Split(delay_test_temp["Local_port"], " ")[1])
			// getdelay.GetTCPDelay(sqlPath)
			delay.GetTCPDelayJSON(configPath)
		case "7":
			process.Stop(configPath)
		case "8", "":
			os.Exit(0)
		case "9":
			process.StartByArgument(configPath, "http")
		case "9b":
			process.StartByArgument(configPath, "httpBp")
		default:
			fmt.Println(languageString["enterError"])
		}
	}
}

func main() {
	configPath := ssrinit.GetConfigAndSQLPath()

	daemon := flag.String("d", "", "d")
	subDaemon := flag.String("sd", "", "sd")
	flag.Parse()

	if *daemon != "" {
		process.Start(configPath)
	}
	if *subDaemon != "" {
		if *subDaemon == "ssr" {
			process.Start(configPath)
		} else if *subDaemon == "http" {
			test.StartHTTP(configPath)
		} else if *subDaemon == "httpBp" {
			test.StartHTTPBypass(configPath)
		} else if *subDaemon == "httpB" {
			test.StartHTTPByArgument()
		} else if *subDaemon == "httpBBp" {
			test.StartHTTPByArgumentBypass()
		}
	} else {
		menu(configPath)
	}
}
