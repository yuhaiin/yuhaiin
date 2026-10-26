package main

import (
	"fmt"
	"os"

	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
)

var help = `Usage:
  yuhaiin [action] [options]

Actions:
  auth        local management administrator bootstrap/recovery
  recovery    encrypted backup key generation and offline archive verification
  install     install yuhaiin
  uninstall   uninstall yuhaiin
  start       start yuhaiin
  stop        stop yuhaiin
  restart     restart yuhaiin
  version     show version
  run         run yuhaiin       [default]

  Options:
    -host, -h  HTTP listen host [default: 0.0.0.0:50051]
    -https     Serve HTTP and HTTPS on the same port [default: true]
    -https-cert TLS certificate PEM file (use with -https-key)
    -https-key  TLS private key PEM file
    -https-names Hostnames/IPs for the generated self-signed certificate
    -path, -p  save data path [default: %s/.yuhaiin]
    -eweb, -e  external web page static files dir
  help        show help
`

func main() {
	action := ""
	args := os.Args[1:]
	if len(os.Args) > 1 {
		action = os.Args[1]
		args = os.Args[2:]
	}

	do := func(f func(args []string) error) {
		if err := f(args); err != nil {
			log.Error(err.Error())
			panic(err)
		}
	}

	switch action {
	case "recovery":
		do(recoveryCommand)
		return
	case "auth":
		do(authCommand)
		return
	case "install":
		do(install)
		return
	case "uninstall":
		do(uninstall)
		return
	case "start":
		do(start)
		return
	case "stop":
		do(stop)
		return
	case "restart":
		do(restart)
		return
	case "update-helper":
		do(updateHelper)
		return
	case "version", "-v", "--version":
		version.Output(os.Stdout)
		return
	case "help", "-h", "--help":
		fmt.Printf(help, configuration.DataDir.Load())
		return
	case "run":
	default:
		args = os.Args[1:]
	}

	if err := run(args); err != nil {
		log.Error(err.Error())
	}
}
