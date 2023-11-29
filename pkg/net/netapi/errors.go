package netapi

import (
	"errors"
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

var ErrBlocked = errors.New("BLOCK")

type errorBlockedImpl struct {
	network statistic.Type
	h       string
}

func NewBlockError(network statistic.Type, hostname string) error {
	return &errorBlockedImpl{network, hostname}
}
func (e *errorBlockedImpl) Error() string {
	return fmt.Sprintf("blocked address %v[%s]", e.network, e.h)
}
func (e *errorBlockedImpl) Is(err error) bool { return errors.Is(err, ErrBlocked) }
