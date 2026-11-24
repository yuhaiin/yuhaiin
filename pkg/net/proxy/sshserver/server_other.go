//go:build !linux || android

package sshserver

import (
	"context"
	"errors"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// Server is unavailable outside Linux hosts (Android is not supported).
type Server struct{ netapi.EmptyInterface }

func NewServer(Config, netapi.Handler) (*Server, error) {
	return nil, errors.New("ssh inbound requires Linux with network namespace privileges")
}

func (*Server) Close() error { return nil }

func RunSFTP([]string) error { return errors.New("SFTP inbound requires Linux") }

// DetectEnvironment reports that SSH sessions are unavailable.
func DetectEnvironment(context.Context) contract.SSHEnvironment {
	return contract.SSHEnvironment{Error: "SSH sessions require Linux"}
}
