//go:build linux && !android

package main

import "testing"

func TestWrapCommandArgumentErrors(t *testing.T) {
	for _, tc := range []struct {
		args      []string
		code      int
		wantError bool
	}{
		{[]string{"-help"}, 0, false},
		{nil, 125, true},
		{[]string{"-unknown-option"}, 125, true},
		{[]string{"--", "/missing/yuhaiin-wrap-program"}, 127, true},
	} {
		code, err := wrapCommand(tc.args)
		if code != tc.code || (err != nil) != tc.wantError {
			t.Fatalf("args %q: %d %v", tc.args, code, err)
		}
	}
}
