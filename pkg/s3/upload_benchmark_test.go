package s3

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
)

// This loopback benchmark includes signing, hashing and HTTP transfer, but not
// SQLite, remote storage durability or physical network throughput.
func BenchmarkS3Upload(b *testing.B) {
	for _, size := range []int{1 << 20, 8 << 20, 32 << 20} {
		b.Run(fmt.Sprintf("%dMiB", size>>20), func(b *testing.B) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					b.Error(err)
				}
				switch {
				case r.Method == http.MethodPost && r.URL.Query().Has("uploads"):
					_, _ = io.WriteString(w, `<InitiateMultipartUploadResult><UploadId>benchmark</UploadId></InitiateMultipartUploadResult>`)
				case r.Method == http.MethodPost:
					_, _ = io.WriteString(w, `<CompleteMultipartUploadResult><ETag>benchmark</ETag></CompleteMultipartUploadResult>`)
				default:
					w.Header().Set("ETag", `"benchmark"`)
				}
			}))
			defer server.Close()
			client, err := NewS3(contractbackup.S3{EndpointURL: server.URL, Bucket: "backups", Region: "us-east-1", AccessKey: "fixture", SecretKey: "fixture"}, direct.Default)
			if err != nil {
				b.Fatal(err)
			}
			// The baseline API predates Close; keep this exact benchmark reproducible
			// against both versions without changing its measured upload call.
			if closer, ok := any(client).(io.Closer); ok {
				defer closer.Close()
			}
			data := bytes.Repeat([]byte("x"), size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := client.Put(b.Context(), data, "state.db"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
