//go:build linux && !android

package sshserver

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/pkg/sftp"
	"golang.org/x/sys/unix"
)

// RunSFTP is the internal re-exec entry point. Session.Spawn drops credentials
// and joins the session namespaces/cgroup before this process is started.
func RunSFTP(readOnlyPaths []string) error {
	if os.Getuid() == 0 || os.Geteuid() == 0 || os.Getegid() == 0 {
		return errors.New("SFTP requires an unprivileged UID and GID")
	}
	return serveSFTP(&sftpStdio{Reader: os.Stdin, Writer: os.Stdout}, readOnlyPaths)
}

type sftpStdio struct {
	io.Reader
	io.Writer
}

func (*sftpStdio) Close() error { return nil }

func serveSFTP(stream io.ReadWriteCloser, paths []string) error {
	directory, err := os.Getwd()
	if err != nil {
		return err
	}
	// Preserve the library's normal host filesystem semantics when no extra
	// restrictions were configured. The kernel enforces the child's UID/GID.
	if len(paths) == 0 {
		server, err := sftp.NewServer(stream, sftp.WithServerWorkingDirectory(directory))
		if err != nil {
			return err
		}
		defer server.Close()
		return sftpServeError(server.Serve())
	}
	policy, err := newSFTPPolicy(paths)
	if err != nil {
		return err
	}
	fs := &sftpFilesystem{policy: policy}
	server := sftp.NewRequestServer(stream, sftp.Handlers{
		FileGet: fs, FilePut: fs, FileCmd: fs, FileList: fs,
	}, sftp.WithStartDirectory(directory))
	defer server.Close()
	return sftpServeError(server.Serve())
}

func sftpServeError(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

type sftpFilesystem struct {
	policy *sftpPolicy
	mu     sync.Mutex
}

func (*sftpFilesystem) Fileread(r *sftp.Request) (io.ReaderAt, error) { return os.Open(r.Filepath) }

func (fs *sftpFilesystem) Filewrite(r *sftp.Request) (io.WriterAt, error) { return fs.OpenFile(r) }

func (fs *sftpFilesystem) OpenFile(r *sftp.Request) (sftp.WriterAtReaderAt, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	p, err := fs.policy.pin(r.Filepath, true, false)
	if err != nil {
		return nil, err
	}
	defer p.parent.Close()
	f := r.Pflags()
	flags := os.O_WRONLY
	if f.Read {
		flags = os.O_RDWR
	}
	if f.Creat {
		flags |= os.O_CREATE
	}
	if f.Excl {
		flags |= os.O_EXCL
	}
	if f.Append {
		flags |= os.O_APPEND
	}
	file, err := p.open(flags, 0o666)
	if err != nil {
		return nil, err
	}
	// Check the opened object before truncating or writing. No pathname is
	// reopened after the policy check, including when a symlink was replaced.
	err = fs.policy.checkFile(file)
	if err == nil && f.Trunc {
		err = file.Truncate(0)
	}
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &sftpWritableFile{File: file, fs: fs, append: f.Append}, nil
}

type sftpWritableFile struct {
	*os.File
	fs     *sftpFilesystem
	append bool
}

func (f *sftpWritableFile) WriteAt(data []byte, offset int64) (int, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if err := f.fs.policy.checkFile(f.File); err != nil {
		return 0, err
	}
	if f.append {
		return f.Write(data)
	}
	return f.File.WriteAt(data, offset)
}

func (fs *sftpFilesystem) Filecmd(r *sftp.Request) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if r.Method == "Symlink" {
		p, err := fs.policy.pin(r.Target, false, false)
		if err != nil {
			return err
		}
		defer p.parent.Close()
		return unix.Symlinkat(r.Filepath, p.fd(), p.name)
	}
	follow := r.Method == "Setstat" || r.Method == "Link"
	moving := r.Method == "Rename" || r.Method == "PosixRename" || r.Method == "Rmdir" || r.Method == "Remove"
	p, err := fs.policy.pin(r.Filepath, follow, moving)
	if err != nil {
		return err
	}
	defer p.parent.Close()
	switch r.Method {
	case "Setstat":
		return fs.setstat(p, r)
	case "Mkdir":
		return unix.Mkdirat(p.fd(), p.name, 0o777)
	case "Remove":
		return unix.Unlinkat(p.fd(), p.name, 0)
	case "Rmdir":
		return unix.Unlinkat(p.fd(), p.name, unix.AT_REMOVEDIR)
	case "Rename", "PosixRename", "Link":
		target, err := fs.policy.pin(r.Target, false, r.Method != "Link")
		if err != nil {
			return err
		}
		defer target.parent.Close()
		if r.Method == "Link" {
			return unix.Linkat(p.fd(), p.name, target.fd(), target.name, 0)
		}
		flags := uint(0)
		if r.Method == "Rename" {
			flags = unix.RENAME_NOREPLACE
		}
		return unix.Renameat2(p.fd(), p.name, target.fd(), target.name, flags)
	default:
		return sftp.ErrSSHFxOpUnsupported
	}
}

func (fs *sftpFilesystem) PosixRename(r *sftp.Request) error { return fs.Filecmd(r) }

func (fs *sftpFilesystem) setstat(p *sftpPath, r *sftp.Request) error {
	file, err := p.open(unix.O_PATH, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return unix.EACCES
	}
	if err := fs.policy.checkFile(file); err != nil {
		return err
	}
	flags, attrs := r.AttrFlags(), r.Attributes()
	if attrs == nil {
		return sftp.ErrSSHFxBadMessage
	}
	if flags.UidGid {
		if err := os.Chown(fdPath(file), int(attrs.UID), int(attrs.GID)); err != nil {
			return err
		}
	}
	if flags.Permissions {
		if err := os.Chmod(fdPath(file), attrs.FileMode()); err != nil {
			return err
		}
	}
	if flags.Size {
		if err := os.Truncate(fdPath(file), int64(attrs.Size)); err != nil {
			return err
		}
	}
	if flags.Acmodtime {
		times := []unix.Timespec{unix.NsecToTimespec(attrs.AccessTime().UnixNano()), unix.NsecToTimespec(attrs.ModTime().UnixNano())}
		return unix.UtimesNanoAt(int(file.Fd()), "", times, unix.AT_EMPTY_PATH)
	}
	return nil
}

func (*sftpFilesystem) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	if r.Method == "List" {
		dir, err := os.Open(r.Filepath)
		if err != nil {
			return nil, err
		}
		defer dir.Close()
		files, err := dir.Readdir(-1)
		return sftpFileList(files), err
	}
	if r.Method == "Stat" {
		info, err := os.Stat(r.Filepath)
		return sftpFileList{info}, err
	}
	return nil, sftp.ErrSSHFxOpUnsupported
}

func (*sftpFilesystem) Lstat(r *sftp.Request) (sftp.ListerAt, error) {
	info, err := os.Lstat(r.Filepath)
	return sftpFileList{info}, err
}

func (*sftpFilesystem) Readlink(path string) (string, error) { return os.Readlink(path) }

func (*sftpFilesystem) RealPath(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return resolveSFTPPath(path, 0)
}

type sftpFileList []os.FileInfo

func (files sftpFileList) ListAt(dst []os.FileInfo, offset int64) (int, error) {
	if offset < 0 {
		return 0, os.ErrInvalid
	}
	if offset >= int64(len(files)) {
		return 0, io.EOF
	}
	n := copy(dst, files[offset:])
	if n < len(dst) {
		return n, io.EOF
	}
	return n, nil
}
