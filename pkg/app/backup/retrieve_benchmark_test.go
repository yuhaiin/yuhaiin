package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
)

// This loopback benchmark includes a new S3 client, signing, streamed disk writes,
// digest verification and durable exclusive publication. The immutable fixture
// is allocated before measurement; B/op reports per-operation allocations, not RSS.
func BenchmarkRecoveryArchiveRetrieval(b *testing.B) {
	for _, size := range []int{1 << 20, 16 << 20} {
		b.Run(fmt.Sprintf("%dMiB", size>>20), func(b *testing.B) {
			content := bytes.Repeat([]byte{0x5a}, size)
			hash := sha256.Sum256(content)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(content) }))
			defer server.Close()
			expected := contractrecovery.Backup{Target: "s3", Size: int64(size), SHA256: hex.EncodeToString(hash[:]), InstanceID: uuid.New().String(), BackupID: uuid.New().String()}
			expected.ObjectKey = "recovery/" + expected.InstanceID + "/" + expected.BackupID + ".yhb"
			options := contract.S3{Enabled: true, EndpointURL: server.URL, Bucket: "fixture", AccessKey: "access", SecretKey: "secret"}
			path := filepath.Join(b.TempDir(), "archive.yhb")
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				if err := FetchArchive(b.Context(), path, options, expected, direct.Default, false); err != nil {
					b.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
