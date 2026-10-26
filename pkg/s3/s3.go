package s3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	MaxObjectBytes = int64(100 << 30)
	// Get is the legacy byte-slice API. Large archives use Download instead.
	MaxLegacyBytes = int64(64 << 20)
	partBytes      = int64(16 << 20)
)

type S3 struct {
	s3c          *awss3.Client
	transport    *http.Transport
	Bucket       string
	StorageClass string
}

func NewS3(opt contractbackup.S3, proxy netapi.Proxy) (*S3, error) {
	if proxy == nil {
		return nil, errors.New("S3 requires an outbound proxy")
	}
	endpoint := strings.TrimSpace(opt.EndpointURL)
	if endpoint != "" {
		if !strings.Contains(endpoint, "://") {
			endpoint = "https://" + endpoint
		}
		u, err := url.Parse(endpoint)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, errors.New("S3 endpoint must be an HTTP(S) URL without credentials, query or fragment")
		}
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			ad, err := netapi.ParseAddress(network, addr)
			if err != nil {
				return nil, err
			}
			return proxy.Conn(ctx, ad)
		},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout: 30 * time.Second, MaxIdleConns: 2, MaxIdleConnsPerHost: 2,
	}
	region := opt.Region
	if region == "" {
		region = "us-east-1"
	}
	options := awss3.Options{
		Region:      region,
		Credentials: credentials.NewStaticCredentialsProvider(opt.AccessKey, opt.SecretKey, ""),
		HTTPClient:  &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		Retryer:     retry.NewStandard(func(o *retry.StandardOptions) { o.MaxAttempts = 3; o.MaxBackoff = 2 * time.Second }),
		// Custom endpoints have always used path-style addressing in this package.
		UsePathStyle:               opt.UsePathStyle || endpoint != "",
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	}
	if endpoint != "" {
		options.BaseEndpoint = new(endpoint)
	}
	return &S3{Bucket: opt.Bucket, StorageClass: opt.StorageClass, transport: transport, s3c: awss3.New(options)}, nil
}

func (s *S3) Close() error { s.transport.CloseIdleConnections(); return nil }
func (s *S3) Put(ctx context.Context, data []byte, file string) error {
	return s.PutReader(ctx, bytes.NewReader(data), int64(len(data)), file)
}

// PutReader streams an immutable snapshot. Large objects use sequential 16 MiB
// sections, at most one in flight. Only the SDK's bounded object retries replay.
func (s *S3) PutReader(ctx context.Context, data io.ReaderAt, size int64, file string) error {
	if size < 0 || size > MaxObjectBytes || data == nil {
		return errors.New("S3 upload size must be between 0 and 100 GiB")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	contentType := "application/octet-stream"
	if filepath.Ext(file) == ".json" {
		contentType = "application/json"
	}
	if size <= partBytes {
		_, err := s.s3c.PutObject(ctx, &awss3.PutObjectInput{
			Bucket: new(s.Bucket), Key: new(file), ContentType: new(contentType), StorageClass: types.StorageClass(s.StorageClass),
			ContentLength: new(size), Body: &contextSection{ctx, io.NewSectionReader(data, 0, size)},
		})
		return err
	}
	created, err := s.s3c.CreateMultipartUpload(ctx, &awss3.CreateMultipartUploadInput{
		Bucket: new(s.Bucket), Key: new(file), ContentType: new(contentType), StorageClass: types.StorageClass(s.StorageClass),
	})
	if err != nil {
		return err
	}
	if created.UploadId == nil || *created.UploadId == "" {
		return errors.New("S3 returned an empty multipart upload ID")
	}
	complete := false
	defer func() {
		if !complete {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_, _ = s.s3c.AbortMultipartUpload(cleanup, &awss3.AbortMultipartUploadInput{Bucket: new(s.Bucket), Key: new(file), UploadId: created.UploadId})
		}
	}()
	parts := make([]types.CompletedPart, 0, (size+partBytes-1)/partBytes)
	for offset := int64(0); offset < size; offset += partBytes {
		length, number := min(partBytes, size-offset), int32(len(parts)+1)
		part, err := s.s3c.UploadPart(ctx, &awss3.UploadPartInput{
			Bucket: new(s.Bucket), Key: new(file), UploadId: created.UploadId, PartNumber: new(number), ContentLength: new(length),
			Body: &contextSection{ctx, io.NewSectionReader(data, offset, length)},
		})
		if err != nil {
			return err
		}
		if part.ETag == nil || *part.ETag == "" {
			return errors.New("S3 returned an empty multipart ETag")
		}
		parts = append(parts, types.CompletedPart{ETag: part.ETag, PartNumber: new(number)})
	}
	_, err = s.s3c.CompleteMultipartUpload(ctx, &awss3.CompleteMultipartUploadInput{
		Bucket: new(s.Bucket), Key: new(file), UploadId: created.UploadId, MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
	})
	complete = err == nil
	return err
}

type contextSection struct {
	ctx context.Context
	*io.SectionReader
}

func (r *contextSection) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.SectionReader.Read(p)
}

// Download leaves staging/cleanup to the caller and enforces the limit even
// when the server omits Content-Length. It never buffers the object in memory.
func (s *S3) Download(ctx context.Context, dst io.Writer, file string, limit int64) (int64, error) {
	if limit < 1 || limit > MaxObjectBytes {
		return 0, errors.New("invalid S3 download limit")
	}
	resp, err := s.s3c.GetObject(ctx, &awss3.GetObjectInput{Bucket: new(s.Bucket), Key: new(file)})
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.ContentLength != nil && *resp.ContentLength > limit {
		return 0, errors.New("S3 object exceeds download limit")
	}
	n, err := io.Copy(dst, io.LimitReader(resp.Body, limit))
	if err != nil {
		return n, err
	}
	var extra [1]byte
	more, err := io.ReadFull(resp.Body, extra[:])
	if more != 0 {
		return n, errors.New("S3 object exceeds download limit")
	}
	if !errors.Is(err, io.EOF) {
		return n, fmt.Errorf("finish S3 download: %w", err)
	}
	return n, nil
}
func (s *S3) Get(ctx context.Context, file string) ([]byte, error) {
	var data bytes.Buffer
	_, err := s.Download(ctx, &data, file, MaxLegacyBytes)
	if err != nil {
		return nil, err
	}
	return data.Bytes(), nil
}
