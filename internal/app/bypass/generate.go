package main

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"flag"
	"os"
)

//go:embed yuhaiin.conf
var data []byte

func main() {
	path := flag.String("des", "", "")
	flag.Parse()

	if path == nil {
		panic("des is empty")
	}

	b := bytes.NewBuffer(nil)

	gw := gzip.NewWriter(b)
	gw.Write(data)
	gw.Close()

	err := os.WriteFile(*path, b.Bytes(), 0644)
	if err != nil {
		panic(err)
	}
}
