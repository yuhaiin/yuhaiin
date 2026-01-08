package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	"github.com/Asutorufa/yuhaiin/pkg/net/relay"
)

func main() {
	target := flag.String("t", "", "target, -t www.example.com:22")
	s5 := flag.String("s", "127.0.0.1:1080", "socks5 server host, -s 127.0.0.1:1080")
	flag.Parse()

	addr, err := netapi.ParseAddress("tcp", *target)
	if err != nil {
		log.Fatal(err)
	}

	host, port, err := net.SplitHostPort(*s5)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := socks5.Dial(host, port, "", "").Conn(context.TODO(), addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "socks5 dial failed: %v, try direct connect\n", err)

		// dialer.DefaultInterfaceName = func() string {
		// 	de, err := interfaces.DefaultRoute()
		// 	if err != nil {
		// 		fmt.Fprintf(os.Stderr, "get default route failed: %v\n", err)
		// 		return ""
		// 	} else {
		// 		fmt.Fprintf(os.Stderr, "default route: %v\n", de.InterfaceName)
		// 		return de.InterfaceName
		// 	}
		// }

		// net.DefaultResolver = &net.Resolver{
		// 	Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		// 		fmt.Fprintf(os.Stderr, "default resolver dial\n")
		// 		return net.Dial("udp", "208.67.222.222:5353")
		// 	},
		// }

		conn, err = dialer.DialContext(context.TODO(), "tcp", *target)
		if err != nil {
			log.Fatal(err)
		} else {
			fmt.Fprintf(os.Stderr, "start relay %v <-> %v\n\n", addr, conn.RemoteAddr())
		}
	} else {
		fmt.Fprintf(os.Stderr, "start relay %v <-> %v\n\n", addr, conn.RemoteAddr())
	}
	defer conn.Close()

	relay.Relay(&stdInOutReadWriteCloser{}, conn)
}

type stdInOutReadWriteCloser struct{}

func (stdInOutReadWriteCloser) Read(b []byte) (int, error)  { return os.Stdin.Read(b) }
func (stdInOutReadWriteCloser) Write(b []byte) (int, error) { return os.Stdout.Write(b) }
func (stdInOutReadWriteCloser) Close() error                { os.Stdin.Close(); return os.Stdout.Close() }
