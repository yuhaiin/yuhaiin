//go:build linux && !android

// Package localwrap launches local commands through isolated inbound networking.
package localwrap

import (
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const maxFrame = 256 << 10
const protocolVersion = 1

type request struct {
	Version int      `json:"version"`
	Argv    []string `json:"argv"`
	Env     []string `json:"env"`
	Dir     string   `json:"dir"`
	TTY     bool     `json:"tty"`
}
type message struct {
	Signal int    `json:"signal,omitzero"`
	Exit   *int   `json:"exit,omitzero"`
	Error  string `json:"error,omitempty"`
}

func writeFrame(w io.Writer, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(b) > maxFrame {
		return errors.New("wrap: message too large")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(b)))
	if _, err := io.Copy(w, strings.NewReader(string(header[:])+string(b))); err != nil {
		return err
	}
	return nil
}
func readFrame(r io.Reader, value any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > maxFrame {
		return errors.New("wrap: invalid message size")
	}
	b := make([]byte, int(n))
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, value)
}

func sendFiles(c *net.UnixConn, files []*os.File) error {
	fds := make([]int, len(files))
	for i, file := range files {
		fds[i] = int(file.Fd())
	}
	n, _, err := c.WriteMsgUnix([]byte{protocolVersion}, unix.UnixRights(fds...), nil)
	if err == nil && n != 1 {
		return io.ErrShortWrite
	}
	return err
}

func receiveFiles(c *net.UnixConn) (_ []*os.File, err error) {
	var payload [1]byte
	oob := make([]byte, unix.CmsgSpace(3*4))
	n, oobn, flags, _, err := c.ReadMsgUnix(payload[:], oob)
	if err != nil {
		return nil, err
	}
	controls, parseErr := unix.ParseSocketControlMessage(oob[:oobn])
	var files []*os.File
	defer func() {
		if err != nil {
			closeFiles(files)
		}
	}()
	for _, control := range controls {
		fds, e := unix.ParseUnixRights(&control)
		if e != nil {
			parseErr = errors.Join(parseErr, e)
			continue
		}
		for _, fd := range fds {
			unix.CloseOnExec(fd)
			files = append(files, os.NewFile(uintptr(fd), "wrap-stdio"))
		}
	}
	if parseErr != nil || flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 || n != 1 || payload[0] != protocolVersion || (len(files) != 1 && len(files) != 3) {
		return nil, errors.New("wrap: invalid descriptor handshake")
	}
	return files, nil
}
func closeFiles(files []*os.File) {
	for _, file := range files {
		_ = file.Close()
	}
}

func (r request) validate() error {
	if r.Version != protocolVersion || len(r.Argv) == 0 || r.Argv[0] == "" || !strings.HasPrefix(r.Dir, "/") {
		return errors.New("wrap: invalid launch request")
	}
	for _, arg := range r.Argv {
		if strings.ContainsRune(arg, 0) {
			return errors.New("wrap: NUL in argument")
		}
	}
	if strings.ContainsRune(r.Dir, 0) {
		return errors.New("wrap: NUL in directory")
	}
	for _, env := range r.Env {
		key, _, ok := strings.Cut(env, "=")
		if !ok || key == "" || strings.ContainsRune(env, 0) {
			return errors.New("wrap: invalid environment")
		}
	}
	return nil
}
