package redirserver

import (
	"errors"
	"net"
)

func handleRedir(req net.Conn) error {
	req.Close()
	return errors.New("not support windows")
}
