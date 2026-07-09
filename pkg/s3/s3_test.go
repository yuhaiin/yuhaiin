package s3

import (
	"context"
	"encoding/json/v2"
	"os"
	"testing"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestS3(t *testing.T) {
	t.Run("marshal config", func(t *testing.T) {
		config := contractbackup.S3{
			Enabled:      true,
			AccessKey:    "access",
			SecretKey:    "secret",
			Bucket:       "bucket",
			Region:       "region",
			EndpointURL:  "endpoint",
			UsePathStyle: true,
		}

		data, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(string(data))
	})

	t.Run("put", func(t *testing.T) {
		t.Skip("requires real S3/R2 credentials and network access")

		data, err := os.ReadFile(".config.json")
		assert.NoError(t, err)

		var config contractbackup.S3
		assert.NoError(t, json.Unmarshal(data, &config))

		s3, err := NewS3(config, direct.Default)
		assert.NoError(t, err)

		assert.NoError(t, s3.Put(context.Background(), []byte("test"), "test.json"))

		data, err = s3.Get(t.Context(), "test.json")
		assert.NoError(t, err)
		assert.Equal(t, "test", string(data))
	})
}
