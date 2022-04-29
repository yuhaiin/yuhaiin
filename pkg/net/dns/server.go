package dns

import (
	"fmt"
	"log"
	"net"
)

func GetReq(req []byte) (resp respHeader, err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = fmt.Errorf("recovering from panic resolve: %v", r)
		}
	}()
	r := &resolver{request: req, aswer: req}
	err = r.header()
	if err != nil {
		return respHeader{}, err
	}

	if r.h.isAnswer {
		return respHeader{}, fmt.Errorf("the request is a answer")
	}

	return r.h, nil
}

func DNSServer() {
	l, err := net.ListenPacket("udp", "127.0.0.1:5333")
	if err != nil {
		panic(err)
	}
	log.Println("127.0.0.1:5333")

	for {
		p := make([]byte, 1024)
		n, addr, err := l.ReadFrom(p)
		if err != nil {
			if e, ok := err.(net.Error); ok {
				if e.Temporary() {
					continue
				}
			}
			panic(err)
		}

		go func(b []byte, addr net.Addr, l net.PacketConn) {
			head, err := GetReq(b)
			if err != nil {
				log.Println(err)
				return
			}

			switch head.dnsType {
			case A:
				log.Println("A")
			case AAAA:
				log.Println("AAAA")
			}

			log.Println(head)

			d, err := net.ListenPacket("udp", "")
			if err != nil {
				log.Println(err)
				return
			}

			_, err = d.WriteTo(b, &net.UDPAddr{IP: net.ParseIP("114.114.114.114"), Port: 53})
			if err != nil {
				log.Println(err)
				return
			}

			z := make([]byte, 1024)
			n, addrs, err := d.ReadFrom(z)
			if err != nil {
				log.Println(err)
				return
			}
			log.Println(addrs)
			l.WriteTo(z[:n], addr)

		}(p[:n], addr, l)
	}

}
