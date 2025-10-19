package s3

import (
	"context"
	"os"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestS3(t *testing.T) {
	t.Run("marshal config", func(t *testing.T) {
		config := config.S3_builder{
			Enabled:      proto.Bool(true),
			AccessKey:    proto.String("access"),
			SecretKey:    proto.String("secret"),
			Bucket:       proto.String("bucket"),
			Region:       proto.String("region"),
			EndpointUrl:  proto.String("endpoint"),
			UsePathStyle: proto.Bool(true),
		}.Build()

		data, err := protojson.MarshalOptions{
			Indent: "\t",
		}.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(string(data))
	})

	t.Run("put", func(t *testing.T) {
		data, err := os.ReadFile(".config.json")
		assert.NoError(t, err)

		var config config.S3
		assert.NoError(t, protojson.Unmarshal(data, &config))

		s3, err := NewS3(&config, direct.Default)
		assert.NoError(t, err)

		assert.NoError(t, s3.Put(context.Background(), []byte("test"), "test.json"))

		data, err = s3.Get(t.Context(), "test.json")
		assert.NoError(t, err)
		assert.Equal(t, "test", string(data))
	})
}
