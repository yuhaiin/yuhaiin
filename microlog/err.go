package microlog

import "fmt"

type ErrErr struct {
	Err string
}

func (e ErrErr) Error() string {
	return fmt.Sprintf(e.Err)
}
