package server

import (
	"fmt"
	"net"
)

func (r *redir) handle(req net.Conn) error {
	req.Close()

	return fmt.Errorf("windows can't support redir")
}
