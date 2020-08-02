package controller

import (
	"testing"
)

func TestRef(t *testing.T) {
	if ref[hTTP] == nil {
		t.Log("nil")
	} else {
		t.Log("not nil")
	}
	if ref[100] == nil {
		t.Log("nil")
	} else {
		t.Log("not nil")
	}
}
