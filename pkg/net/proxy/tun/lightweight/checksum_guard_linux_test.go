package lightweight

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

// An assembly load outside the input must fault instead of silently reading
// accessible heap padding. Guard both ends of the writable middle page.
func TestChecksumGuardPages(t *testing.T) {
	page := os.Getpagesize()
	t.Logf("guard page size=%d", page)
	b, err := unix.Mmap(-1, 0, page*3, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Munmap(b); err != nil {
			t.Error(err)
		}
	})
	for _, guard := range [][]byte{b[:page], b[2*page:]} {
		if err := unix.Mprotect(guard, unix.PROT_NONE); err != nil {
			t.Fatal(err)
		}
	}
	data := b[page : 2*page]
	for i := range data {
		data[i] = byte(i*31 + 17)
	}
	for _, n := range []int{0, 1, 2, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1500, page} {
		for _, p := range [][]byte{data[:n], data[page-n:]} {
			if got, want := fold(sumBytes(p, 65535)), checksum.Checksum(p, 65535); got != want {
				t.Fatalf("guarded size=%d checksum=%04x want=%04x", n, got, want)
			}
		}
	}
}
