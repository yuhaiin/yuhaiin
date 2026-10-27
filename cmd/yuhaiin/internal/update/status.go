package updatecmd

import (
	"encoding/json/v2"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/update/maintenance"
)

func Status(args []string) error { return executeUpdateStatus(args, os.Stdout) }
func executeUpdateStatus(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("update-status", flag.ContinueOnError)
	directory := flags.String("path", configuration.DataDir.Load(), "deployment data directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected update-status arguments")
	}
	record, err := maintenance.Read(*directory)
	if err != nil {
		return err
	}
	if record == nil {
		return json.MarshalWrite(output, struct {
			State string `json:"state"`
		}{"no_operation"})
	}
	return json.MarshalWrite(output, record.OperationStatus)
}
