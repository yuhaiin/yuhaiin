package helper

import (
	"fmt"
	"os"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

// joinSocketGroup makes gid the real and effective group of the process.
// Sockets record the group when they are created, and the kill switch lets
// TCP and UDP sockets of this group through. Only root can do this.
func joinSocketGroup(gid int) (bool, string) {
	if gid <= 0 {
		return false, "the protection service has no socket group"
	}
	if os.Getegid() == gid {
		return true, ""
	}
	if os.Geteuid() != 0 {
		return false, "Yuhaiin is not running as root and cannot join the " + GroupName + " group"
	}
	if err := syscall.Setgid(gid); err != nil {
		return false, fmt.Sprintf("join the %s group: %v", GroupName, err)
	}
	log.Info("network protection: joined the socket group; new connections pass the kill switch", "group", GroupName, "gid", gid)
	return true, ""
}
