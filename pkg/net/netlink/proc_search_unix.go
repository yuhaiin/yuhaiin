//go:build (linux && !android) || darwin

package netlink

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Keep the scanner independent of the syscall ABI so it can be exercised with
// a proc-shaped directory fixture on both Linux and Darwin. Names passed to
// these calls are borrowed, NUL-terminated directory entries, never strings.
type procSearchCalls struct {
	openat     func(int, []byte) (int, error)
	readlinkat func(int, []byte, []byte) (int, error)
}

type procSearchBuffers struct {
	pids [8192]byte
	fds  [8192]byte
	link [32]byte
	exe  [4096]byte
}

var procSearchPool = sync.Pool{New: func() any { return new(procSearchBuffers) }}
var procFDName = [...]byte{'f', 'd', 0}
var procExeName = [...]byte{'e', 'x', 'e', 0}

func resolveProcessNameByProcSearchAt(root string, inode, uid uint32, calls procSearchCalls) (string, uint, error) {
	scratch := procSearchPool.Get().(*procSearchBuffers)
	defer procSearchPool.Put(scratch)
	return findProcessInProc(root, inode, uid, calls, scratch)
}

func findProcessInProc(root string, inode, uid uint32, calls procSearchCalls, scratch *procSearchBuffers) (string, uint, error) {
	procFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = unix.Close(procFD) }()

	var expected [32]byte
	target := append(expected[:0], "socket:["...)
	target = strconv.AppendUint(target, uint64(inode), 10)
	target = append(target, ']')
	var path string
	var pid uint
	var matchErr error
	_, err = scanProcDirectory(procFD, scratch.pids[:], func(name []byte) bool {
		id, ok := procNumber(name)
		if !ok {
			return false
		}
		pidFD, err := calls.openat(procFD, name)
		if err != nil {
			return false
		}
		defer func() { _ = unix.Close(pidFD) }()
		var stat unix.Stat_t
		if unix.Fstat(pidFD, &stat) != nil || stat.Uid != uid {
			return false
		}
		fdFD, err := calls.openat(pidFD, procFDName[:])
		if err != nil {
			return false
		}
		matched, _ := scanProcDirectory(fdFD, scratch.fds[:], func(fdName []byte) bool {
			if _, ok := procNumber(fdName); !ok {
				return false
			}
			n, err := calls.readlinkat(fdFD, fdName, scratch.link[:])
			return err == nil && bytes.Equal(scratch.link[:n], target)
		})
		_ = unix.Close(fdFD)
		if !matched {
			return false
		}
		// Resolve exe through the already-open PID directory, rather than reopening
		// a /proc/PID path that could now refer to a recycled PID.
		pid = uint(id)
		path, matchErr = readProcExecutable(pidFD, scratch.exe[:], calls)
		return true
	})
	if pid != 0 {
		return path, pid, matchErr
	}
	if err != nil {
		return "", 0, err
	}
	return "", 0, fmt.Errorf("inode %d of uid %d not found", inode, uid)
}

// scanProcDirectory visits names directly in a fixed-size getdents buffer.
// The byte slice includes its terminator and is valid only during visit.
func scanProcDirectory(fd int, buf []byte, visit func([]byte) bool) (bool, error) {
	const nameOffset = int(unsafe.Offsetof(unix.Dirent{}.Name))
	const reclenOffset = int(unsafe.Offsetof(unix.Dirent{}.Reclen))
	for {
		n, err := unix.ReadDirent(fd, buf)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return false, err
		}
		if n == 0 {
			return false, nil
		}
		for records := buf[:n]; len(records) != 0; {
			if len(records) < nameOffset+1 {
				return false, unix.EIO
			}
			size := int(binary.NativeEndian.Uint16(records[reclenOffset : reclenOffset+2]))
			if size < nameOffset+1 || size > len(records) {
				return false, unix.EIO
			}
			name := records[nameOffset:size]
			end := bytes.IndexByte(name, 0)
			if end < 0 {
				return false, unix.EIO
			}
			if visit(name[:end+1]) {
				return true, nil
			}
			records = records[size:]
		}
	}
}

func procNumber(name []byte) (uint32, bool) {
	if len(name) < 2 || name[len(name)-1] != 0 {
		return 0, false
	}
	var n uint32
	for _, ch := range name[:len(name)-1] {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		digit := uint32(ch - '0')
		if n > (^uint32(0)-digit)/10 {
			return 0, false
		}
		n = n*10 + digit
	}
	return n, true
}

func readProcExecutable(fd int, buf []byte, calls procSearchCalls) (string, error) {
	for {
		n, err := calls.readlinkat(fd, procExeName[:], buf)
		if err != nil {
			return "", err
		}
		if n < len(buf) {
			return string(buf[:n]), nil
		}
		// readlink silently truncates. Preserve os.Readlink's growing-buffer
		// behavior for long executable paths, without retaining the large buffer.
		if len(buf) >= 1<<20 {
			return "", unix.ENAMETOOLONG
		}
		buf = make([]byte, len(buf)*2)
	}
}
