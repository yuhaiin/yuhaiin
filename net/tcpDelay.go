package getdelay

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"../config"
	"../config/configJson"
	"../subscription"
)

// TCPDelay get once delay by tcp
func TCPDelay(address, port string) (time.Duration, error) {
	//fmt.Print("tcp connecting")
	timeNow := time.Now()
	conn, err := net.DialTimeout("tcp", address+":"+port, 2*time.Second)
	if err != nil {
		if time.Since(timeNow) > 2*time.Second {
			log.Println("tcp timeout,tcp connect time over 2s")
		} else {
			log.Println("tcp connect error")
		}
		log.Println(err)
		return 999 * time.Hour, err
	}
	defer conn.Close()
	delay := time.Since(timeNow)
	fmt.Print(delay, " ")
	return delay, nil
}

func getTCPDelayAverage(server, serverPort string) time.Duration {
	var delay [3]time.Duration
	var err error
	for i := 0; i < 3; i++ {
		delay[i], err = TCPDelay(server, serverPort)
		if err != nil {
			// log.Println("tcp connect error")
			// log.Println(err)
			continue
		}
	}
	return (delay[0] + delay[1] + delay[2]) / 3
}

// GetTCPDelay get delay by tcp
func GetTCPDelay(sqlPath string) {
	subscription.ShowAllNodeIDAndRemarks(sqlPath)
	db, err := sql.Open("sqlite3", sqlPath)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer db.Close()

	//获取服务器条数
	var num int
	query, err := db.Prepare("select count(*) from SSR_info")
	if err != nil {
		return
	}
	query.QueryRow().Scan(&num)

	var SelectNum int
	for {
		fmt.Print(config.GetFunctionString()["returnMenu"])
		fmt.Scanln(&SelectNum)
		switch {
		case SelectNum == 0:
			return
		case SelectNum > 0 && SelectNum <= num:
			var remarks, server, serverPort string
			err = db.QueryRow("SELECT remarks,server,server_port FROM SSR_info where id = "+strconv.Itoa(SelectNum)).Scan(&remarks, &server, &serverPort)
			if err != nil {
				log.Println("cant find sever and server_port.")
				log.Println(err)
				return
			}
			fmt.Print(remarks + "delay(3 times): ")
			fmt.Println("average:", getTCPDelayAverage(server, serverPort))
		default:
			fmt.Println(config.GetFunctionString()["enterError"])
			continue
		}
	}
}

// GetTCPDelayJSON get delay by tcp
func GetTCPDelayJSON(configPath string) {
	for {
		node, err := configJSON.SelectNode(configPath)
		if err != nil {
			return
		}
		if node.Server == "" {
			break
		}
		fmt.Print(node.Remarks + "delay(3 times): ")
		fmt.Println("average:", getTCPDelayAverage(node.Server, node.ServerPort))
	}
}
