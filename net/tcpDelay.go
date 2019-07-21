package getdelay

import (
	"fmt"
	"log"
	"net"
	"time"

	"../config/configJson"
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
