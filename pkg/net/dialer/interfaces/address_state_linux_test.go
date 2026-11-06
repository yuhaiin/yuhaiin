//go:build !android

package interfaces

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxSourceAddressValidity(t *testing.T) {
	for _, tc := range []struct {
		flags  int
		usable bool
	}{
		{0, true}, {unix.IFA_F_DEPRECATED, true}, {unix.IFA_F_TENTATIVE, false},
		{unix.IFA_F_TENTATIVE | unix.IFA_F_OPTIMISTIC, true}, {unix.IFA_F_DADFAILED, false},
		{unix.IFA_F_DADFAILED | unix.IFA_F_OPTIMISTIC, false},
	} {
		if got := usableLinuxAddress(tc.flags); got != tc.usable {
			t.Errorf("flags=%x usable=%v want=%v", tc.flags, got, tc.usable)
		}
	}
}
