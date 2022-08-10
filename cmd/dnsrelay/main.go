package main

import (
	"flag"
	"log"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

func main() {
	host := flag.String("host", "", "host")
	tar := flag.String("target", "", "target")
	flag.Parse()

	if *host == "" || *tar == "" {
		log.Fatal("host and target is required")
	}

	ll, err := net.ListenPacket("udp", *host)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("listening on", ll.LocalAddr())

	target, err := net.ResolveUDPAddr("udp", *tar)
	if err != nil {
		log.Fatal(err)
	}

	for {
		buf := utils.GetBytes(utils.DefaultSize)
		n, form, err := ll.ReadFrom(buf)
		if err != nil {
			log.Fatal(err)
		}

		log.Println("read", n, "bytes from", form)

		go func(buf []byte, n int, form net.Addr) {
			defer utils.PutBytes(buf)
			l, err := net.ListenPacket("udp", "")
			if err != nil {
				log.Fatal(err)
			}
			defer l.Close()

			l.SetWriteDeadline(time.Now().Add(time.Minute))
			_, err = l.WriteTo(buf[:n], target)
			if err != nil {
				log.Println(err)
				return
			}

			l.SetReadDeadline(time.Now().Add(time.Minute))
			n, _, err = l.ReadFrom(buf)
			if err != nil {
				log.Println(err)
				return
			}

			_, err = ll.WriteTo(buf[:n], form)
			if err != nil {
				log.Println(err)
				return
			}
		}(buf, n, form)
	}
}
