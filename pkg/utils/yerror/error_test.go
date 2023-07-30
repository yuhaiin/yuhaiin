package yerror

import (
	"errors"
	"testing"
)

func TestError(t *testing.T) {
	Ignore(0, errors.New("ignore error"))
}
