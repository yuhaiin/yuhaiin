//go:build linux && !android

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestProtectionCommandNeedsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as root")
	}
	var out, errOut bytes.Buffer
	if code := protectionCommand([]string{"status"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "only be read as root") {
		t.Fatalf("status: %d %q", code, out.String())
	}
	out.Reset()
	if code := protectionCommand([]string{"disable", "--recovery", "--yes"}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "sudo yuhaiin protection disable --recovery") {
		t.Fatalf("disable: %d %q", code, errOut.String())
	}
}
