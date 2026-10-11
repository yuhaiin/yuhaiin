package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

func main() {
	serverKey := mustHexKey("SERVER_PRIVATE_KEY")
	clientKey := mustHexKey("CLIENT_PUBLIC_KEY")
	tunDevice, err := tun.CreateTUN("awg0", 1420)
	if err != nil {
		log.Fatal(err)
	}
	defer tunDevice.Close()
	for _, args := range [][]string{
		{"addr", "add", "10.8.0.1/24", "dev", "awg0"},
		{"link", "set", "awg0", "up"},
	} {
		if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			log.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, output)
		}
	}

	dev := device.NewDevice(tunDevice, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "awg test server"))
	config := fmt.Sprintf("private_key=%s\nlisten_port=51820\njc=4\njmin=40\njmax=70\npublic_key=%s\nallowed_ip=10.8.0.2/32\n\n", serverKey, clientKey)
	if err := dev.IpcSetOperation(strings.NewReader(config)); err != nil {
		log.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		log.Fatal(err)
	}
	defer dev.Close()

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(10, 8, 0, 1), Port: 4242})
	if err != nil {
		log.Fatal(err)
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp", "10.8.0.1:4243")
	if err != nil {
		log.Fatal(err)
	}
	defer tcp.Close()
	go echoUDP(udp)
	go echoTCP(tcp)
	fmt.Println("AmneziaWG test server ready")

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}

func mustHexKey(name string) string {
	key, err := base64.StdEncoding.DecodeString(os.Getenv(name))
	if err != nil || len(key) != 32 {
		log.Fatalf("%s must be a base64 32-byte key", name)
	}
	return hex.EncodeToString(key)
}

func echoUDP(conn *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, peer, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if _, err := conn.WriteToUDP(buf[:n], peer); err != nil {
			return
		}
	}
}

func echoTCP(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}()
	}
}
