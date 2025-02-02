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
  install     install yuhaiin
  uninstall   uninstall yuhaiin
  start       start yuhaiin
  stop        stop yuhaiin
  restart     restart yuhaiin
  version     show version
  run         run yuhaiin 		[default]
	Options:
  		-host, -h  gRPC and http listen host [default: 0.0.0.0:50051]
  		-path, -p  save data path [default: %s/.yuhaiin]
  		-eweb, -e  external web page
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
