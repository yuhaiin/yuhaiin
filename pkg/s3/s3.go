package s3

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/backup"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3 struct {
	Bucket string
	s3c    *s3.Client
}

func NewS3(opt *backup.S3, proxy netapi.Proxy) (*S3, error) {
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(opt.GetRegion()),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(opt.GetAccessKey(), opt.GetSecretKey(), "")),
		config.WithBaseEndpoint(opt.GetEndpointUrl()),
		config.WithHTTPClient(&http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					ad, err := netapi.ParseAddress(network, addr)
					if err != nil {
						return nil, err
					}
					return proxy.Conn(ctx, ad)
				},
			},
		}),
	)
	if err != nil {
		return nil, err
	}
	return &S3{
		Bucket: opt.GetBucket(),
		s3c: s3.NewFromConfig(cfg, func(o *s3.Options) {
			o.UsePathStyle = opt.GetUsePathStyle()
		}),
	}, nil
}

func (s *S3) Put(ctx context.Context, data []byte, file string) error {
	contentType := "application/octet-stream"

	if filepath.Ext(file) == ".json" {
		contentType = "application/json"
	}

	_, err := s.s3c.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        &s.Bucket,
		Key:           &file,
		Body:          bytes.NewReader(data),
		ContentLength: aws.Int64(int64(len(data))),
		ContentType:   aws.String(contentType),
	})
	return err
}

func (s *S3) Get(ctx context.Context, file string) ([]byte, error) {
	resp, err := s.s3c.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &s.Bucket,
		Key:    &file,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
