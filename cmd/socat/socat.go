package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
)

func main() {
	target := flag.String("t", "", "target, -t www.example.com:22")
	s5 := flag.String("s", "127.0.0.1:1080", "socks5 server host, -s 127.0.0.1:1080")
	flag.Parse()

	addr, err := netapi.ParseAddress(statistic.Type_tcp, *target)
	if err != nil {
		log.Fatal(err)
	}

	host, port, err := net.SplitHostPort(*s5)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := socks5.Dial(host, port, "", "").Conn(context.TODO(), addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(os.Stderr, "start relay %v <-> %v\n\n", addr, conn.RemoteAddr())

	relay.Relay(&stdInOutReadWriteCloser{}, conn)
}

type stdInOutReadWriteCloser struct{}

func (stdInOutReadWriteCloser) Read(b []byte) (int, error)  { return os.Stdin.Read(b) }
func (stdInOutReadWriteCloser) Write(b []byte) (int, error) { return os.Stdout.Write(b) }
func (stdInOutReadWriteCloser) Close() error                { os.Stdin.Close(); return os.Stdout.Close() }
