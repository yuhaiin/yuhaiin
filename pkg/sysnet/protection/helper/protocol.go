package helper

import (
	"bufio"
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
)

// The service speaks newline-delimited JSON over a Unix socket. There are
// only four operations; none takes a command, a rule, or a path.
const (
	OpStatus  = "status"
	OpEnable  = "enable"
	OpUpdate  = "update"
	OpDisable = "disable"
)

// maxFrame bounds one message (a policy with the maximum number of networks
// fits comfortably).
const maxFrame = 8 << 20

type Request struct {
	ID     uint64             `json:"id"`
	Op     string             `json:"op"`
	Policy *protection.Policy `json:"policy,omitzero"`
	// By names the requester for the saved state (api, cli).
	By string `json:"by,omitzero"`
}

type Response struct {
	ID     uint64                    `json:"id"`
	Status *sysnet.ProtectionStatus  `json:"status,omitzero"`
	Error  *sysnet.ProtectionProblem `json:"error,omitzero"`
}

func readFrame(r *bufio.Reader, v any) error {
	line, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return errors.New("message too large")
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(line, v)
}

func writeFrame(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

// Client talks to the service. One connection is kept open: the service
// binds the runtime part of a policy (tunnels, own traffic) to it, and drops
// that part as soon as the connection closes, so a crashed core never keeps
// its allowances.
type Client struct {
	path string
	by   string

	mu      sync.Mutex
	conn    net.Conn
	reader  *bufio.Reader
	next    uint64
	session uint64
}

// NewClient connects lazily to the service socket.
func NewClient(by string) *Client { return &Client{path: Socket, by: by} }

func newClientAt(path, by string) *Client { return &Client{path: path, by: by} }

// Session increases whenever a new connection was opened, which means the
// service no longer has the runtime policy sent on the previous one.
func (c *Client) Session() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session
}

// ErrServiceUnavailable means the service socket does not answer.
var ErrServiceUnavailable = errors.New("the Yuhaiin Network Protection service is not reachable")

func (c *Client) dialLocked(ctx context.Context) error {
	if c.conn != nil {
		return nil
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.path)
	if err != nil {
		return c.unavailable(err)
	}
	c.conn, c.reader = conn, bufio.NewReaderSize(conn, maxFrame)
	c.session++
	return nil
}

func (c *Client) unavailable(err error) error {
	if _, statErr := os.Stat(PlistPath); errors.Is(statErr, os.ErrNotExist) && c.path == Socket {
		return &protection.ProblemError{Problem: sysnet.ProtectionProblem{Code: sysnet.ProblemServiceMissing,
			Message: "The Yuhaiin Network Protection service is not installed",
			Hint:    "Install Yuhaiin as a system service with: sudo yuhaiin install"}}
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, os.ErrPermission) {
		return &protection.ProblemError{Problem: sysnet.ProtectionProblem{Code: sysnet.ProblemPermission,
			Message: "Permission denied connecting to the Network Protection service", Hint: "Run the command with sudo"}}
	}
	return &protection.ProblemError{Problem: sysnet.ProtectionProblem{Code: sysnet.ProblemServiceDown,
		Message: ErrServiceUnavailable.Error() + ": " + err.Error(),
		Hint:    "Start it with: sudo launchctl kickstart system/" + Label + ". To remove protection without it: sudo yuhaiin protection disable --recovery"}}
}

func (c *Client) closeLocked() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn, c.reader = nil, nil
	}
}

// Call sends one request. A broken connection is reopened once.
func (c *Client) Call(ctx context.Context, op string, policy *protection.Policy) (sysnet.ProtectionStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if err := c.dialLocked(ctx); err != nil {
			return sysnet.ProtectionStatus{}, err
		}
		c.next++
		req := Request{ID: c.next, Op: op, Policy: policy, By: c.by}
		deadline := time.Now().Add(60 * time.Second)
		if d, ok := ctx.Deadline(); ok {
			deadline = d
		}
		_ = c.conn.SetDeadline(deadline)
		var resp Response
		err := writeFrame(c.conn, req)
		if err == nil {
			err = readFrame(c.reader, &resp)
		}
		if err != nil {
			c.closeLocked()
			lastErr = c.unavailable(err)
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if resp.ID != req.ID {
			c.closeLocked()
			return sysnet.ProtectionStatus{}, fmt.Errorf("protection service answered request %d with %d", req.ID, resp.ID)
		}
		if resp.Error != nil {
			status := sysnet.ProtectionStatus{}
			if resp.Status != nil {
				status = *resp.Status
			}
			return status, &protection.ProblemError{Problem: *resp.Error}
		}
		if resp.Status == nil {
			return sysnet.ProtectionStatus{}, errors.New("protection service sent no status")
		}
		return *resp.Status, nil
	}
	return sysnet.ProtectionStatus{}, lastErr
}

// Close closes the connection. The service drops this connection's runtime
// policy and keeps protecting.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
	return nil
}

// WaitService waits until the service answers.
func WaitService(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		c := NewClient("cli")
		_, err := c.Call(ctx, OpStatus, nil)
		c.Close()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(200 * time.Millisecond):
		}
	}
}
