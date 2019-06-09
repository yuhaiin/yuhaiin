package main

import (
	"flag"
	"fmt"
	"os"

	ssr_init "./init"
	getdelay "./net"
	ssr_process "./process"
	"./subscription"
	_ "github.com/mattn/go-sqlite3"
)

func menu(configPath, sqlPath string) {
	//初始化
	ssr_init.Init(configPath, sqlPath)
	//获取当前配置文件路径和可执行文件路径
	ssr_init.MenuInit(configPath)
	//获取当前节点
	fmt.Println("当前使用节点:", subscription.GetNowNode(sqlPath))
	for {
		fmt.Print("1.开启ssr\n2.更换节点/查看所有节点\n3.更新所有订阅\n4.添加订阅链接\n5.删除订阅链接\n6.获取延迟\n7.结束ssr后台\n8.结束此程序(ssr后台运行)\n>>>")

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
			fmt.Print("请输入要添加的订阅链接(一条):")
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
			fmt.Println("输入错误")
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
