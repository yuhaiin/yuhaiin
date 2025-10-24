package s3

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/rhnvrm/simples3"
)

type S3 struct {
	Bucket       string
	StorageClass string
	s3c          *simples3.S3
}

func NewS3(opt *config.S3, proxy netapi.Proxy) (*S3, error) {
	s3 := simples3.New(opt.GetRegion(), opt.GetAccessKey(), opt.GetSecretKey())
	if opt.GetEndpointUrl() != "" {
		s3.SetEndpoint(opt.GetEndpointUrl())
	}

	s3.SetClient(&http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ad, err := netapi.ParseAddress(network, addr)
				if err != nil {
					return nil, err
				}
				return proxy.Conn(ctx, ad)
			},
		},
	})

	return &S3{
		Bucket:       opt.GetBucket(),
		s3c:          s3,
		StorageClass: opt.GetStorageClass(),
	}, nil
}

func (s *S3) Put(ctx context.Context, data []byte, file string) error {
	contentType := "application/octet-stream"

	if filepath.Ext(file) == ".json" {
		contentType = "application/json"
	}

	_, err := s.s3c.FilePut(simples3.UploadInput{
		Bucket:      s.Bucket,
		ObjectKey:   file,
		ContentType: contentType,
		Body:        bytes.NewReader(data),
	})
	return err
}

func (s *S3) Get(ctx context.Context, file string) ([]byte, error) {
	resp, err := s.s3c.FileDownload(simples3.DownloadInput{
		Bucket:    s.Bucket,
		ObjectKey: file,
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Close(); err != nil {
			log.Error("close s3 response body failed", "err", err)
		}
	}()
	return io.ReadAll(resp)
}
