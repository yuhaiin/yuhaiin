package GetDelay

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"../subscription"
	_ "github.com/mattn/go-sqlite3"
)

func Tcp_delay(adress, port string) (time.Duration, error) {
	//fmt.Print("tcp connecting")
	time_ := time.Now()
	conn, err := net.DialTimeout("tcp", adress+":"+port, 2*time.Second)
	if err != nil {
		if time.Since(time_) > 2*time.Second {
			log.Println("tcp timeout,tcp connect time over 2s")
		} else {
			log.Println("tcp connect error")
		}
		log.Println(err)
		return 999 * time.Hour, err
	}
	defer conn.Close()
	delay := time.Since(time_)
	fmt.Print(delay, " ")
	return delay, nil
}

func get_tcp_delay_average(server, server_port string) time.Duration {
	var delay [3]time.Duration
	var err error
	for i := 0; i < 3; i++ {
		delay[i], err = Tcp_delay(server, server_port)
		if err != nil {
			// log.Println("tcp connect error")
			// log.Println(err)
			continue
		}
	}
	/*
		if err != nil {

			//return -1, err
		}*/

	//delay, err := tcp_delay(server, server_port)
	return (delay[0] + delay[1] + delay[2]) / 3
}
func Get_tcp_delay(sql_path string) {

	subscription.List_list_db(sql_path)
	db, err := sql.Open("sqlite3", sql_path)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer db.Close()

	//获取服务器条数
	var num int
	query, err := db.Prepare("select count(*) from SSR_info")
	query.QueryRow().Scan(&num)

	var select_ int
	for {
		fmt.Print("select one node to test delay >>> ")
		fmt.Scanln(&select_)
		if select_ == 0 {
			return
		} else if select_ > 0 && select_ <= num {
			var remarks, server, server_port string
			err = db.QueryRow("SELECT remarks,server,server_port FROM SSR_info where id = "+strconv.Itoa(select_)).Scan(&remarks, &server, &server_port)
			if err != nil {
				log.Println("cant find sever and server_port.")
				log.Println(err)
				return
			}
			fmt.Print(remarks + "delay(3 times): ")
			fmt.Println("average:", get_tcp_delay_average(server, server_port))
		} else {
			fmt.Println("enter error,please retry.")
			continue
		}
	}
}
