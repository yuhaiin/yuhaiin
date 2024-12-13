package yuhaiin

import (
	"fmt"
	"strings"
	"testing"

	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/kv"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestStore(t *testing.T) {
	InitDB("", "")
	defer CloseStore()
	GetStore("default").PutFloat("float", 3.1415926)
	t.Log(GetStore("default").GetFloat("float"))
	assert.Equal(t, float32(3.1415926), GetStore("default").GetFloat("float"))
}

func TestMultipleProcess(t *testing.T) {
	t.Log(string(disAllowAppList))

	InitDB("", "")
	defer CloseStore()

	GetStore("default").PutFloat("float", 3.1415926)
	t.Log(GetStore("default").GetFloat("float"))
}

func TestV(t *testing.T) {
	cli, err := kv.NewClient("test/kv.sock")
	if err != nil {
		panic(fmt.Errorf("new kv client failed: %w", err))
	}
	defer cli.Close()
}

func TestXxx(t *testing.T) {
	ss := &pc.Setting{}

	msg := ss.ProtoReflect().Descriptor()

	str := &strings.Builder{}
	for i := 0; i < msg.Fields().Len(); i++ {
		fd := msg.Fields().Get(i)
		printValuePath(str, fd)
	}

	t.Log(str.String())
}

func printValuePath(s *strings.Builder, msg protoreflect.FieldDescriptor) {
	if msg.Kind() == protoreflect.MessageKind {
		for i := 0; i < msg.Message().Fields().Len(); i++ {
			fd := msg.Message().Fields().Get(i)
			printValuePath(s, fd)
		}
		return
	}
	if msg.Kind() == protoreflect.EnumKind {
		vs := msg.Enum().Values()
		for i := 0; i < vs.Len(); i++ {
			v := vs.Get(i)
			fmt.Println(v.Name(), v.FullName(), msg.Enum().FullName())
		}
	}
	fmt.Fprintf(s, "// %s\n", msg.FullName())
}
