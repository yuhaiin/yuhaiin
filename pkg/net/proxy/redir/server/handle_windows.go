package server

import (
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func handle(req net.Conn, f netapi.Handler) error {
	req.Close()

	return fmt.Errorf("windows can't support redir")
}
