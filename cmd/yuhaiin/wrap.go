package main

import (
	"context"
	"errors"
	"flag"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/localwrap"
	"golang.org/x/term"
)

func wrapCommand(args []string) (int, error) {
	flags := flag.NewFlagSet("wrap", flag.ContinueOnError)
	socket := flags.String("socket", localwrap.DefaultSocket, "local wrap service socket")
	noTTY := flags.Bool("no-tty", false, "disable automatic terminal allocation")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 125, err
	}
	return localwrap.Run(context.Background(), localwrap.Options{Socket: *socket, Argv: flags.Args(), Terminal: !*noTTY && term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))})
}
