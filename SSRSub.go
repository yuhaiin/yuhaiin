package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	config "./config"
	ssr_init "./init"
	getdelay "./net"
	ssr_process "./process"
	"./subscription"
	_ "github.com/mattn/go-sqlite3"
)

func menu(configPath, sqlPath string) {
	languageString := config.GetFunctionString()
	//初始化
	ssr_init.Init(configPath, sqlPath)
	//获取当前配置文件路径和可执行文件路径
	executablePath, err := os.Executable()
	if err != nil {
		log.Println(err)
	}

	fmt.Println(languageString["configPath"] + configPath)
	fmt.Println(languageString["executablePath"] + executablePath)
	//获取当前节点
	fmt.Println(languageString["nowNode"], subscription.GetNowNode(sqlPath))
	for {
		fmt.Print(languageString["menu"])

		var selectTemp string
		fmt.Scanln(&selectTemp)

		switch selectTemp {
		case "1":
			// ssr_process.Start(path, db_path)
			ssr_process.StartByArgument(configPath, sqlPath)
		case "2":
			_, exist := ssr_process.Get(configPath)
			selectB := subscription.ChangeNowNode(sqlPath)
			if exist == true && selectB != 0 {
				ssr_process.Stop(configPath)
				// ssr_process.Start(path, db_path)
				ssr_process.StartByArgument(configPath, sqlPath)
			}
			// } else {
			// 	subscription.Ssr_server_node_change(db_path)
			// }
		case "3":
			subscription.DeleteAllNode(sqlPath)
			subscription.AddAllNodeFromLink(sqlPath)
		case "4":
			fmt.Print(">>> ")
			var linkTemp string
			fmt.Scanln(&linkTemp)
			subscription.AddLink(linkTemp, sqlPath)
		case "5":
			subscription.LinkDelete(sqlPath)
		case "6":
			//delay_test_temp := config.Read_config_file(path)
			//GetDelay.Get_delay(strings.Split(delay_test_temp["Local_address"], " ")[1], strings.Split(delay_test_temp["Local_port"], " ")[1])
			getdelay.GetTCPDelay(sqlPath)
		case "7":
			ssr_process.Stop(configPath)
		case "8":
			os.Exit(0)
		default:
			fmt.Println(languageString["enterError"])
		}
	}
}

func main() {
	configPath, sqlPath := ssr_init.GetConfigAndSQLPath()

	daemon := flag.Bool("d", false, "d")
	flag.Parse()
	if *daemon == true {
		ssr_process.Start(configPath, sqlPath)
	} else {
		menu(configPath, sqlPath)
	}
}
