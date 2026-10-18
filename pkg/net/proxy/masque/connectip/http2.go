package connectip

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

const maxStreamBuffer = 32 << 10

type HTTP2ClientConn struct {
	roundTripper http.RoundTripper
	cloudflare   bool
}

func NewHTTP2ClientConn(rt http.RoundTripper) *HTTP2ClientConn {
	return &HTTP2ClientConn{roundTripper: rt}
}

func NewCloudflareHTTP2ClientConn(rt http.RoundTripper) *HTTP2ClientConn {
	return &HTTP2ClientConn{roundTripper: rt, cloudflare: true}
}

func (c *HTTP2ClientConn) Dial(req *Request) (*Conn, *http.Response, error) {
	httpReq := req.httpRequest()
	if httpReq.URL == nil {
		return nil, nil, errors.New("connect-ip: request URL is nil")
	}
	if httpReq.Host == "" && httpReq.URL.Host == "" {
		return nil, nil, errors.New("connect-ip: request needs a host")
	}

	ctx := httpReq.Context()
	streamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, cancel)
	body := NewStreamBuffer()
	r := httpReq.Clone(streamCtx)
	if c.cloudflare {
		r.Header.Del(http3.CapsuleProtocolHeader)
		r.Header.Set("Cf-Connect-Proto", cloudflareProtocol)
		r.Header.Set("Pq-Enabled", "false")
		if _, _, err := net.SplitHostPort(r.Host); err != nil {
			r.Host = net.JoinHostPort(strings.Trim(r.Host, "[]"), "443")
		}
	} else {
		r.Header[":protocol"] = []string{requestProtocol}
	}
	r.Body = body
	rsp, err := c.roundTripper.RoundTrip(r)
	if !stop() {
		if err == nil {
			rsp.Body.Close()
		}
		err = context.Cause(ctx)
	}
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("connect-ip: failed to send request: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		cancel()
		rsp.Body.Close()
		return nil, rsp, fmt.Errorf("connect-ip: server responded with %d", rsp.StatusCode)
	}
	str := &http2Stream{
		reader: bufio.NewReader(rsp.Body),
		body:   body,
		rsp:    rsp.Body,
		cancel: cancel,
	}
	if c.cloudflare {
		return newBareProxiedConn(str), rsp, nil
	}
	return newProxiedConn(str), rsp, nil
}

type http2Stream struct {
	reader *bufio.Reader
	body   *StreamBuffer
	rsp    io.Closer
	cancel context.CancelFunc
}

func (s *http2Stream) Read(b []byte) (int, error)         { return s.reader.Read(b) }
func (s *http2Stream) ReadByte() (byte, error)            { return s.reader.ReadByte() }
func (s *http2Stream) Write(b []byte) (int, error)        { return s.body.Write(b) }
func (s *http2Stream) Close() error                       { return s.body.Close() }
func (s *http2Stream) CancelRead(quic.StreamErrorCode)    { s.abort() }
func (s *http2Stream) CancelWrite(quic.StreamErrorCode)   { s.abort() }
func (s *http2Stream) SetWriteDeadline(t time.Time) error { return s.body.SetWriteDeadline(t) }

func (s *http2Stream) abort() {
	s.cancel()
	s.body.CloseWithError(net.ErrClosed)
	s.rsp.Close()
}

type StreamBuffer struct {
	mu       sync.Mutex
	cond     sync.Cond
	buf      []byte
	head     int
	size     int
	closed   bool
	err      error
	deadline time.Time
	timer    *time.Timer
}

func NewStreamBuffer() *StreamBuffer {
	b := &StreamBuffer{}
	b.cond.L = &b.mu
	return b
}

func (b *StreamBuffer) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.size == 0 && !b.closed && b.err == nil {
		b.cond.Wait()
	}
	if b.err != nil {
		return 0, b.err
	}
	if b.size == 0 {
		return 0, io.EOF
	}
	n := min(len(p), b.size)
	first := copy(p[:n], b.buf[b.head:min(b.head+n, len(b.buf))])
	copy(p[first:n], b.buf[:n-first])
	b.head = (b.head + n) % maxStreamBuffer
	b.size -= n
	b.cond.Broadcast()
	return n, nil
}

func (b *StreamBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	written := 0
	for len(p) > 0 {
		switch {
		case b.err != nil:
			return written, b.err
		case b.closed:
			return written, io.ErrClosedPipe
		case !b.deadline.IsZero() && !time.Now().Before(b.deadline):
			return written, os.ErrDeadlineExceeded
		case b.size < maxStreamBuffer:
			if b.buf == nil {
				b.buf = make([]byte, maxStreamBuffer)
			}
			n := min(len(p), maxStreamBuffer-b.size)
			tail := (b.head + b.size) % maxStreamBuffer
			first := copy(b.buf[tail:], p[:n])
			copy(b.buf, p[first:n])
			b.size += n
			written += n
			p = p[n:]
			b.cond.Broadcast()
			continue
		}
		b.cond.Wait()
	}
	return written, nil
}

func (b *StreamBuffer) Close() error {
	b.mu.Lock()
	b.closed = true
	if b.timer != nil {
		b.timer.Stop()
	}
	b.cond.Broadcast()
	b.mu.Unlock()
	return nil
}

func (b *StreamBuffer) CloseWithError(err error) {
	b.mu.Lock()
	if b.err == nil {
		b.err = err
		b.buf = nil
		b.size = 0
	}
	if b.timer != nil {
		b.timer.Stop()
	}
	b.cond.Broadcast()
	b.mu.Unlock()
}

func (b *StreamBuffer) SetWriteDeadline(t time.Time) error {
	b.mu.Lock()
	b.deadline = t
	if b.timer != nil {
		b.timer.Stop()
	}
	b.cond.Broadcast()
	if d := time.Until(t); !t.IsZero() && d > 0 && !b.closed && b.err == nil {
		if b.timer == nil {
			b.timer = time.AfterFunc(d, func() {
				b.mu.Lock()
				b.cond.Broadcast()
				b.mu.Unlock()
			})
		} else {
			b.timer.Reset(d)
		}
	}
	b.mu.Unlock()
	return nil
}

type http2ResponseStream struct {
	reader     *bufio.Reader
	body       io.Closer
	w          io.Writer
	controller *http.ResponseController
}

func (s *http2ResponseStream) Read(b []byte) (int, error) { return s.reader.Read(b) }
func (s *http2ResponseStream) ReadByte() (byte, error)    { return s.reader.ReadByte() }

func (s *http2ResponseStream) Write(b []byte) (int, error) {
	n, err := s.w.Write(b)
	if err == nil {
		err = s.controller.Flush()
	}
	return n, err
}

func (s *http2ResponseStream) Close() error                     { return nil }
func (s *http2ResponseStream) CancelRead(quic.StreamErrorCode)  { s.body.Close() }
func (s *http2ResponseStream) CancelWrite(quic.StreamErrorCode) { s.body.Close() }
func (s *http2ResponseStream) SetWriteDeadline(t time.Time) error {
	return s.controller.SetWriteDeadline(t)
}
