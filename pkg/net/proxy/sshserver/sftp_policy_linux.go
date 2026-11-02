//go:build linux && !android

package sshserver

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// sftpPolicy restricts SFTP paths, without changing host permissions or shell
// access. Keep both configured and resolved paths so aliases cannot discard a
// restriction. Parent directories are pinned before each filesystem mutation.
type sftpPolicy struct{ readOnly []string }

func newSFTPPolicy(paths []string) (*sftpPolicy, error) {
	p := new(sftpPolicy)
	for _, path := range paths {
		if !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
			return nil, errors.New("SFTP read-only paths must be absolute")
		}
		path = filepath.Clean(path)
		real, err := resolveSFTPPath(path, 0)
		if err != nil {
			return nil, err
		}
		p.readOnly = append(p.readOnly, path, real)
	}
	return p, nil
}

// Resolve even missing destinations and dangling links, so creating through a
// symlink into a protected directory is checked against its actual target.
func resolveSFTPPath(path string, links int) (string, error) {
	if links > 40 {
		return "", unix.ELOOP
	}
	real, err := filepath.EvalSymlinks(path)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return real, err
	}
	if target, err := os.Readlink(path); err == nil {
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		return resolveSFTPPath(target, links+1)
	}
	parent := filepath.Dir(path)
	if parent == path {
		return "", err
	}
	real, err = resolveSFTPPath(parent, links)
	return filepath.Join(real, filepath.Base(path)), err
}

func pathWithin(path, directory string) bool {
	return path == directory || directory == "/" || strings.HasPrefix(path, directory+"/")
}

func (p *sftpPolicy) check(path string, moving bool) error {
	for _, root := range p.readOnly {
		// Moving an ancestor would also move the protected subtree and make
		// a path-based rule ineffective on subsequent requests.
		if pathWithin(path, root) || moving && pathWithin(root, path) {
			return unix.EACCES
		}
	}
	return nil
}

type sftpPath struct {
	parent *os.File
	name   string
}

func fdPath(file *os.File) string {
	return "/proc/self/fd/" + strconv.FormatUint(uint64(file.Fd()), 10)
}

func (p *sftpPolicy) checkFile(file *os.File) error {
	path, err := os.Readlink(fdPath(file))
	if err != nil {
		return err
	}
	return p.check(path, false)
}

func (p *sftpPolicy) pin(path string, follow, moving bool) (*sftpPath, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := p.check(path, moving); err != nil {
		return nil, err
	}
	var real string
	if follow {
		real, err = resolveSFTPPath(path, 0)
	} else {
		real, err = resolveSFTPPath(filepath.Dir(path), 0)
		real = filepath.Join(real, filepath.Base(path))
	}
	if err != nil {
		return nil, err
	}
	if err := p.check(real, moving); err != nil {
		return nil, err
	}
	fd, err := unix.Open(filepath.Dir(real), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parent := os.NewFile(uintptr(fd), filepath.Dir(real))
	actual, err := os.Readlink(fdPath(parent))
	if err == nil {
		err = p.check(filepath.Join(actual, filepath.Base(real)), moving)
	}
	if err != nil {
		_ = parent.Close()
		return nil, err
	}
	return &sftpPath{parent: parent, name: filepath.Base(real)}, nil
}

func (p *sftpPath) fd() int { return int(p.parent.Fd()) }

func (p *sftpPath) open(flags int, mode uint32) (*os.File, error) {
	fd, err := unix.Openat(p.fd(), p.name, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), p.name), nil
}
