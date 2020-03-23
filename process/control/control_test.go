package ServerControl

import "testing"

func TestControl_Start(t *testing.T) {
	x, err := NewControl()
	if err != nil {
		t.Error(err)
	}
	x.Start()
}
