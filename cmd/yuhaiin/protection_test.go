//go:build !darwin && !windows && (!linux || android)

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestProtectionCommandUnsupported(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := protectionCommand([]string{"status"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "Unsupported") {
		t.Fatalf("status: %d %q %q", code, out.String(), errOut.String())
	}
	out.Reset()
	if code := protectionCommand([]string{"disable", "--recovery", "--yes"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "nothing to disable") {
		t.Fatalf("disable: %d %q", code, out.String())
	}
	if code := protectionCommand([]string{"bogus"}, &out, &errOut); code != 2 {
		t.Fatalf("unknown command exit %d", code)
	}
}
