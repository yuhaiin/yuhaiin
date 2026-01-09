package route

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
		return uri{}, err
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
		return nil, fmt.Errorf("get path failed: %s", url)
	}

	return os.Open(path)
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
	if _, err := os.Stat(d.GetPath(url)); err == nil || !os.IsNotExist(err) {
		return err
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
		return err
	}

	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ad, err := netapi.ParseAddress(network, addr)
				if err != nil {
					return nil, err
				}

				return d.dialer().Conn(ctx, ad)
			},
		},
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Warn("close response body failed", "err", err)
		}
	}()

	if resp.StatusCode != 200 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status code: %d, data: %s", resp.StatusCode, string(data))
	}

	// Download to a temporary file first to ensure atomicity of the file update.
	tmpFile, err := os.CreateTemp(d.path, "download-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	_, copyErr := io.Copy(tmpFile, resp.Body)
	closeErr := tmpFile.Close()

	if copyErr != nil {
		return fmt.Errorf("copy to temp file: %w", copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close temp file: %w", closeErr)
	}

	if beforeWrite != nil {
		beforeWrite()
	}

	finalPath := filepath.Join(d.path, hexName(url, url))
	if err := os.Rename(tmpFile.Name(), finalPath); err != nil {
		return fmt.Errorf("rename temp file to final path: %w", err)
	}

	return nil
}

func hexName(name, url string) string {
	h := sha256.New()

	_, _ = io.WriteString(h, name)
	_, _ = io.WriteString(h, url)

	return hex.EncodeToString(h.Sum(nil))
}
