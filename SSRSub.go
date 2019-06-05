package main

import (
	"fmt"
	"os"
	"runtime"

	ssr_init "./init"
	getdelay "./net"
	ssr_process "./process"
	"./subscription"
	_ "github.com/mattn/go-sqlite3"
)

func menu_db(path, db_path string) {
	//初始化
	ssr_init.Init(path, db_path)
	//获取当前配置文件路径和可执行文件路径
	ssr_init.Menu_init(path)
	//获取当前节点
	subscription.Get_now_node(db_path)
	for {
		fmt.Print("1.开启ssr\n2.更换节点/查看所有节点\n3.更新所有订阅\n4.添加订阅链接\n5.删除订阅链接\n6.获取延迟\n7.结束ssr后台\n8.结束此程序(ssr后台运行)\n>>>")

		var select_temp string
		fmt.Scanln(&select_temp)

		switch select_temp {
		case "1":
			ssr_process.Start(path, db_path)
		case "2":
			_, exist := ssr_process.Get(path)
			select_ := subscription.Ssr_server_node_change(db_path)
			if exist == true && select_ != 0 {
				ssr_process.Stop(path)
				ssr_process.Start(path, db_path)
			}
			// } else {
			// 	subscription.Ssr_server_node_change(db_path)
			// }
		case "3":
			subscription.Delete_config_db(db_path)
			subscription.Add_config_db(db_path)
		case "4":
			fmt.Print("请输入要添加的订阅链接(一条):")
			var link_temp string
			fmt.Scanln(&link_temp)
			subscription.Subscription_link_add(link_temp, db_path)
		case "5":
			subscription.Subscription_link_delete(db_path)
		case "6":
			//delay_test_temp := config.Read_config_file(path)
			//GetDelay.Get_delay(strings.Split(delay_test_temp["Local_address"], " ")[1], strings.Split(delay_test_temp["Local_port"], " ")[1])
			getdelay.Get_tcp_delay(db_path)
		case "7":
			ssr_process.Stop(path)
		case "8":
			os.Exit(0)
		default:
			fmt.Println("输入错误\n")
		}
	}
}

func main() {
	var config_path, sql_path string
	if runtime.GOOS == "windows" {
		config_path = os.Getenv("USERPROFILE") + "\\Documents\\SSRSub"
		sql_path = config_path + "\\SSR_config.db"
	} else {
		config_path = os.Getenv("HOME") + "/.config/SSRSub"
		sql_path = config_path + "/SSR_config.db"
	}
	menu_db(config_path, sql_path)
}
