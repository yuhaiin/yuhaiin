package dns

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

type DOT struct {
	DNS
	host   string
	subnet *net.IPNet
}

func NewDOT(host string) *DOT {
	return &DOT{
		host: host,
	}
}

func (d *DOT) Search(domain string) ([]net.IP, error) {
	conn, err := net.DialTimeout("tcp", d.host, time.Second*5)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %v", err)
	}
	servername, _, err := net.SplitHostPort(d.host)
	conn = tls.Client(conn, &tls.Config{
		ServerName:         servername,
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
	})
	defer conn.Close()
	return dnsCommon(domain, d.subnet, func(reqData []byte) (body []byte, err error) {
		length := len(reqData) // dns over tcp, prefix two bytes is request data's length
		reqData = append([]byte{byte(length >> 8), byte(length - ((length >> 8) << 8))}, reqData...)
		_, err = conn.Write(reqData)
		if err != nil {
			return nil, fmt.Errorf("write data failed: %v", err)
		}

		leg := make([]byte, 2)
		_, err = conn.Read(leg)
		if err != nil {
			return nil, fmt.Errorf("read data length from server failed %v", err)
		}
		all := make([]byte, int(leg[0])<<8+int(leg[1]))
		_, err = conn.Read(all)
		if err != nil {
			return nil, fmt.Errorf("read data from server failed: %v", err)
		}
		return all, err
	})
}
