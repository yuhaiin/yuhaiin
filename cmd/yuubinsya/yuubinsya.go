package main

import (
	"flag"
	"log"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
)

func main() {
	host := flag.String("h", "", "-h, listen addr")
	password := flag.String("p", "", "-p, password")
	certFile := flag.String("c", "", "-c, server cert pem")
	keyFile := flag.String("k", "", "-k, server key pem")
	quic := flag.Bool("quic", false, "-quic")
	flag.Parse()

	var err error
	var certPEM, keyPEM []byte

	if *certFile != "" && *keyFile != "" {
		certPEM, err = os.ReadFile(*certFile)
		if err != nil {
			log.Fatal(err)
		}
		keyPEM, err = os.ReadFile(*keyFile)
		if err != nil {
			log.Fatal(err)
		}
	}

	y, err := yuubinsya.NewServer(*host, *password, certPEM, keyPEM, *quic)
	if err != nil {
		log.Fatal(err)
	}

	if *quic {
		err = y.StartQUIC()
	} else {
		err = y.Start()
	}

	if err != nil {
		log.Fatal(err)
	}
}
