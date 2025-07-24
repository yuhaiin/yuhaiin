package s3

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/backup"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type S3 struct {
	Bucket       string
	StorageClass string
	s3c          *minio.Client
}

func NewS3(opt *backup.S3, proxy netapi.Proxy) (*S3, error) {
	uri, err := url.Parse(opt.GetEndpointUrl())
	if err != nil {
		return nil, err
	}

	minioClient, err := minio.New(uri.Host, &minio.Options{
		Creds:  credentials.NewStaticV4(opt.GetAccessKey(), opt.GetSecretKey(), ""),
		Secure: uri.Scheme == "https",
		Region: opt.GetRegion(),
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
	if err != nil {
		return nil, err
	}

	return &S3{
		Bucket:       opt.GetBucket(),
		s3c:          minioClient,
		StorageClass: opt.GetStorageClass(),
	}, nil
}

func (s *S3) Put(ctx context.Context, data []byte, file string) error {
	contentType := "application/octet-stream"

	if filepath.Ext(file) == ".json" {
		contentType = "application/json"
	}

	_, err := s.s3c.PutObject(ctx, s.Bucket,
		file, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{
			ContentType:  contentType,
			StorageClass: s.StorageClass,
		})
	return err
}

func (s *S3) Get(ctx context.Context, file string) ([]byte, error) {
	resp, err := s.s3c.GetObject(ctx, s.Bucket,
		file, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer resp.Close()
	return io.ReadAll(resp)
}
