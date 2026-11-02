//go:build !linux || android

package localwrap

import (
	"context"
	"errors"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

var errUnsupported = errors.New("wrap: Linux network namespaces are required")

type Server struct{}

func NewServer(Config, netapi.Handler) (*Server, error)  { return nil, errUnsupported }
func (*Server) Close() error                             { return nil }
func (*Server) UpdateFakeIPRanges([2]netip.Prefix) error { return errUnsupported }
func Run(context.Context, Options) (int, error)          { return 125, errUnsupported }
