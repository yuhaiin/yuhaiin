package yuhaiin

import (
	"fmt"
	"strings"
	"testing"

	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestStore(t *testing.T) {
	GetStore().PutFloat("float", 3.1415926)
	t.Log(GetStore().GetFloat("float"))
	assert.Equal(t, float32(3.1415926), GetStore().GetFloat("float"))
}

func TestMultipleProcess(t *testing.T) {
	GetStore().PutFloat("float", 3.1415926)
	t.Log(GetStore().GetFloat("float"))
}

func TestXxx(t *testing.T) {
	ss := &pc.Setting{}

	msg := ss.ProtoReflect().Descriptor()

	str := &strings.Builder{}
	for i := range msg.Fields().Len() {
		fd := msg.Fields().Get(i)
		printValuePath(str, fd)
	}

	t.Log(str.String())
}

func printValuePath(s *strings.Builder, msg protoreflect.FieldDescriptor) {
	if msg.Kind() == protoreflect.MessageKind {
		for i := range msg.Message().Fields().Len() {
			fd := msg.Message().Fields().Get(i)
			printValuePath(s, fd)
		}
		return
	}
	if msg.Kind() == protoreflect.EnumKind {
		vs := msg.Enum().Values()
		for i := range vs.Len() {
			v := vs.Get(i)
			fmt.Println(v.Name(), v.FullName(), msg.Enum().FullName())
		}
	}
	fmt.Fprintf(s, "// %s\n", msg.FullName())
}

func TestMemoryDB(t *testing.T) {
	memoryDB.PutString("key1", "value1")
	memoryDB.PutInt("key2", 42)
	memoryDB.PutBoolean("key3", true)
	memoryDB.PutLong("key4", 1234567890)
	memoryDB.PutFloat("key5", 3.14)
	memoryDB.PutBytes("key6", []byte{0x01, 0x02, 0x03})

	assert.Equal(t, "value1", memoryDB.GetString("key1"))
	assert.Equal(t, int32(42), memoryDB.GetInt("key2"))
	assert.Equal(t, true, memoryDB.GetBoolean("key3"))
	assert.Equal(t, int64(1234567890), memoryDB.GetLong("key4"))
	assert.Equal(t, float32(3.14), memoryDB.GetFloat("key5"))
}
