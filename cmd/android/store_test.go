package yuhaiin

import (
	"fmt"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/protos/kv"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestStore(t *testing.T) {
	assert.NoError(t, InitDB("", ""))
	defer CloseStore()
	GetStore("default").PutFloat("float", 3.1415926)
	t.Log(GetStore("default").GetFloat("float"))
	assert.Equal(t, float32(3.1415926), GetStore("default").GetFloat("float"))
}

func TestMultipleProcess(t *testing.T) {
	assert.NoError(t, InitDB("", ""))
	defer CloseStore()

	GetStore("default").PutFloat("float", 3.1415926)
	t.Log(GetStore("default").GetFloat("float"))

	time.Sleep(time.Second * 10)
}

func TestV(t *testing.T) {
	cli, err := kv.NewClient("test/kv.sock")
	if err != nil {
		panic(fmt.Errorf("new kv client failed: %w", err))
	}
	defer cli.Close()
}
