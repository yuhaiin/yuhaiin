package route

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type Downloader struct {
	dialer func() netapi.Proxy
	path   string
}

// sourceError retains the cause for errors.Is while keeping URL-bearing
// transport errors out of status messages and logs.
type sourceError struct {
	operation string
	cause     error
}

func (e *sourceError) Error() string {
	switch {
	case errors.Is(e.cause, context.Canceled):
		return e.operation + ": canceled"
	case errors.Is(e.cause, context.DeadlineExceeded):
		return e.operation + ": timed out"
	case errors.Is(e.cause, os.ErrNotExist):
		return e.operation + ": not found"
	case errors.Is(e.cause, os.ErrPermission):
		return e.operation + ": permission denied"
	default:
		if timeout, ok := errors.AsType[net.Error](e.cause); ok && timeout.Timeout() {
			return e.operation + ": timed out"
		}
		if _, ok := errors.AsType[*tls.CertificateVerificationError](e.cause); ok {
			return e.operation + ": TLS certificate verification failed"
		}
		if _, ok := errors.AsType[*net.DNSError](e.cause); ok {
			return e.operation + ": DNS lookup failed"
		}
		return e.operation
	}
}

func (e *sourceError) Unwrap() error { return e.cause }

type uri struct {
	scheme string
	path   string
}

func NewDownloader(path string, dialer func() netapi.Proxy) *Downloader {
	return &Downloader{
		path:   path,
		dialer: dialer,
	}
}

func (d *Downloader) parseURI(urlstr string) (uri, error) {
	url, err := url.Parse(urlstr)
	if err != nil {
		return uri{}, &sourceError{operation: "invalid route source", cause: err}
	}

	if url.Scheme == "file" {
		if runtime.GOOS == "windows" {
			url.Path = strings.TrimPrefix(url.Path, "/")
		}
		return uri{
			scheme: url.Scheme,
			path:   url.Path,
		}, nil
	} else {
		return uri{
			scheme: url.Scheme,
			path:   url.Path,
		}, nil
	}
}

func (d *Downloader) GetReader(url string) (io.ReadCloser, error) {
	path := d.GetPath(url)
	if path == "" {
		return nil, errors.New("invalid route source")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, &sourceError{operation: "route source cache unavailable", cause: err}
	}
	return file, nil
}

func (d *Downloader) GetPath(url string) string {
	u, err := d.parseURI(url)
	if err != nil {
		log.Warn("parse uri failed", "err", err)
		return ""
	}

	if u.scheme == "file" {
		return u.path
	}

	return filepath.Join(d.path, hexName(url, url))
}

func (d *Downloader) DownloadIfNotExists(ctx context.Context, url string, beforeWrite func()) error {
	if _, err := os.Stat(d.GetPath(url)); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return &sourceError{operation: "route source cache unavailable", cause: err}
	}

	return d.Download(ctx, url, beforeWrite)
}

func (d *Downloader) Download(ctx context.Context, url string, beforeWrite func()) error {
	u, err := d.parseURI(url)
	if err != nil {
		return err
	}

	if u.scheme == "file" {
		return nil
	}

	err = os.MkdirAll(d.path, os.ModePerm)
	if err != nil {
		return &sourceError{operation: "route source storage unavailable", cause: err}
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			ad, err := netapi.ParseAddress(network, addr)
			if err != nil {
				return nil, err
			}

			return d.dialer().Conn(ctx, ad)
		},
	}
	defer transport.CloseIdleConnections()
	hc := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return &sourceError{operation: "invalid route source", cause: err}
	}

	resp, err := hc.Do(req)
	if err != nil {
		return &sourceError{operation: "route source request failed", cause: err}
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Warn("close route source response failed", "err", &sourceError{operation: "route source response close failed", cause: err})
		}
	}()

	if resp.StatusCode != 200 {
		// Error bodies may echo credentials, and an untrusted server can send
		// an arbitrarily large response. The status is sufficient for diagnosis.
		return fmt.Errorf("HTTP status: %d", resp.StatusCode)
	}

	// Download to a temporary file first to ensure atomicity of the file update.
	tmpFile, err := os.CreateTemp(d.path, "download-*.tmp")
	if err != nil {
		return &sourceError{operation: "route source temporary file unavailable", cause: err}
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	_, copyErr := io.Copy(tmpFile, resp.Body)
	closeErr := tmpFile.Close()

	if copyErr != nil {
		return &sourceError{operation: "route source copy failed", cause: copyErr}
	}
	if closeErr != nil {
		return &sourceError{operation: "route source temporary file close failed", cause: closeErr}
	}

	if beforeWrite != nil {
		beforeWrite()
	}

	finalPath := filepath.Join(d.path, hexName(url, url))
	if err := os.Rename(tmpFile.Name(), finalPath); err != nil {
		return &sourceError{operation: "route source cache update failed", cause: err}
	}

	return nil
}

func hexName(name, url string) string {
	h := sha256.New()

	_, _ = io.WriteString(h, name)
	_, _ = io.WriteString(h, url)

	return hex.EncodeToString(h.Sum(nil))
}
