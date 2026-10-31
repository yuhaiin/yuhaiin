package node

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type budgetMemoryConn struct {
	net.Conn
	bytes atomic.Int64
}

func (c *budgetMemoryConn) Read(b []byte) (int, error) {
	clear(b)
	c.bytes.Add(int64(len(b)))
	return len(b), nil
}
func (c *budgetMemoryConn) Write(b []byte) (int, error) {
	c.bytes.Add(int64(len(b)))
	return len(b), nil
}

func TestByteBudgetIncludesConcurrentReadsAndWritesAcrossStreams(t *testing.T) {
	const limit = 65536 + 1024
	b := newByteBudgetProxy(netapi.NewErrProxy(errors.New("unused")), limit)
	var actual atomic.Int64
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			raw := new(budgetMemoryConn)
			c := &probeBudgetConn{Conn: raw, b: b}
			defer func() { actual.Add(raw.bytes.Load()) }()
			for {
				_, err := c.Write(bytes.Repeat([]byte{1}, 137))
				if err != nil {
					if !errors.Is(err, errProbeByteBudget) {
						t.Error(err)
					}
					return
				}
				_, err = c.Read(make([]byte, 251))
				if err != nil {
					if !errors.Is(err, errProbeByteBudget) {
						t.Error(err)
					}
					return
				}
			}
		})
	}
	wg.Wait()
	if actual.Load() != limit || b.remaining.Load() != 0 {
		t.Fatal("transport exceeded reserved bytes", actual.Load(), b.remaining.Load())
	}
}
func TestByteBudgetReturnsUnusedReadAllowance(t *testing.T) {
	b := newByteBudgetProxy(netapi.NewErrProxy(errors.New("unused")), 10)
	raw := &shortBudgetConn{Reader: bytes.NewReader([]byte{1, 2, 3})}
	c := &probeBudgetConn{Conn: raw, b: b}
	data, err := io.ReadAll(c)
	if err != nil || len(data) != 3 || b.remaining.Load() != 7 {
		t.Fatal(data, err, b.remaining.Load())
	}
}

type shortBudgetConn struct {
	net.Conn
	io.Reader
}

func (c *shortBudgetConn) Read(b []byte) (int, error) { return c.Reader.Read(b) }
