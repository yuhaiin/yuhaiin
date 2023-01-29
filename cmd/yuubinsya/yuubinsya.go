package main

import (
	"flag"
	"log"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
)

func main() {
	host := flag.String("h", "", "-h")
	serverName := flag.String("s", "", "-s")
	password := flag.String("p", "", "-p")
	certFile := flag.String("c", "", "-c")
	keyFile := flag.String("k", "", "-k")
	flag.Parse()

	certPEM, err := os.ReadFile(*certFile)
	if err != nil {
		log.Fatal(err)
	}
	keyPEM, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatal(err)
	}

	y, err := yuubinsya.NewServer(*host, *serverName, *password, certPEM, keyPEM)
	if err != nil {
		log.Fatal(err)
	}

	if err = y.Start(); err != nil {
		log.Fatal(err)
	}
}
