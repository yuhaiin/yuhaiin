package compatibility

import (
	"os"
	"testing"
)

// Executed by test-linux-abi.sh inside real glibc/musl/scratch environments.
func TestLinuxABIEnvironment(t *testing.T) {
	want := os.Getenv("YUHAIIN_TEST_LINUX_ABI")
	if want == "" {
		t.Skip("requires the Linux ABI environment fixture")
	}
	if got := LinuxABI(); got != want {
		t.Fatalf("host ABI %q, want %q", got, want)
	}
	candidate := os.Getenv("YUHAIIN_GLIBC_CANDIDATE")
	needs, err := RequiresGlibc(candidate)
	if err != nil || !needs {
		t.Fatalf("glibc target inspection: %v, %v", needs, err)
	}
	if err := VerifyHostLibc(candidate); (err == nil) != (want == "glibc") {
		t.Fatalf("candidate admission for %s: %v", want, err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	needs, err = RequiresGlibc(self)
	if err != nil || needs {
		t.Fatalf("static probe: %v, %v", needs, err)
	}
	if err := VerifyHostLibc(self); err != nil {
		t.Fatal(err)
	}
}
