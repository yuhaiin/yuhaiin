package yerror

import (
	"errors"
	"log"
	"testing"
)

func TestError(t *testing.T) {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	Ignore(0, errors.New("ignore error"))
}
