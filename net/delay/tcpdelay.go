package delay

import (
	"log"
	"net"
	"time"
)

// TCPDelay get once delay by tcp
func TCPDelay(address, port string) (time.Duration, bool, error) {
	timeNow := time.Now()
	conn, err := net.DialTimeout("tcp", address+":"+port, 3*time.Second)
	if err != nil {
		if time.Since(timeNow) > 3*time.Second {
			log.Println("tcp timeout,tcp connect time over 5s")
			return 999 * time.Hour, false, err
		}
		log.Println("tcp connect error")
		return 999 * time.Hour, false, err
	}
	defer func() {
		_ = conn.Close()
	}()
	delay := time.Since(timeNow)
	return delay, true, nil
}
