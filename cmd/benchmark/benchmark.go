package main

import (
	"context"
	"flag"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
)

func main() {
	l := flag.String("l", "", "listener")
	t := flag.String("t", "", "target")
	s := flag.String("s", "", "socks5")
	flag.Parse()

	sh, sp, err := net.SplitHostPort(*s)
	if err != nil {
		panic(err)
	}

	ta, err := netapi.ParseAddress(0, *t)
	if err != nil {
		panic(err)
	}

	lis, err := net.Listen("tcp", *l)
	if err != nil {
		panic(err)
	}

	p := socks5.Dial(sh, sp, "", "")

	for {
		conn, err := lis.Accept()
		if err != nil {
			panic(err)
		}

		go func() {
			defer conn.Close()

			lconn, err := p.Conn(context.TODO(), ta)
			if err != nil {
				panic(err)
			}
			defer lconn.Close()

			relay.Relay(conn, lconn)
		}()
	}

}
