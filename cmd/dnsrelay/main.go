package main

import (
	"flag"
	"log"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
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
		buf := pool.GetBytes(pool.DefaultSize)
		n, form, err := ll.ReadFrom(buf)
		if err != nil {
			log.Fatal(err)
		}

		log.Println("read", n, "bytes from", form)

		go func() {
			if err := handle(ll, buf, n, form, target); err != nil {
				log.Println(err)
			}
		}()
	}
}

func handle(local net.PacketConn, buf []byte, n int, form, target net.Addr) error {
	defer pool.PutBytes(buf)
	l, err := net.ListenPacket("udp", "")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	l.SetWriteDeadline(time.Now().Add(time.Minute))
	_, err = l.WriteTo(buf[:n], target)
	if err != nil {
		return err
	}

	l.SetReadDeadline(time.Now().Add(time.Minute))
	n, _, err = l.ReadFrom(buf)
	if err != nil {
		return err
	}

	_, err = local.WriteTo(buf[:n], form)
	if err != nil {
		return err
	}

	return nil
}
