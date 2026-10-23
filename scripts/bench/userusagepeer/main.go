// userusagepeer is an independent loopback echo process for usage benchmarks.
package main

import (
	"encoding/json/v2"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer udp.Close()
	data, err := json.Marshal(map[string]string{"tcp": tcp.Addr().String(), "udp": udp.LocalAddr().String()})
	if err != nil {
		log.Fatal(err)
	}
	if _, err := os.Stdout.Write(append(data, '\n')); err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, peer, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			if _, err := udp.WriteTo(buffer[:n], peer); err != nil {
				return
			}
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)
	<-stop
}
