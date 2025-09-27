package bbolt

import "testing"

func TestBBoltDBLogger(t *testing.T) {
	BBoltDBLogger{}.Info("test")
}
