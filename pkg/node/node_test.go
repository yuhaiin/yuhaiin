package node

import (
	"log"
	"reflect"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
)

func TestDelete(t *testing.T) {
	a := []string{"a", "b", "c"}

	for i := range a {
		if a[i] != "b" {
			continue
		}

		log.Println(i, a[:i], a[i:])
		a = append(a[:i], a[i+1:]...)
		break
	}

	t.Log(a)
}

func TestProtoMsgType(t *testing.T) {
	p := &protocol.Protocol{
		Protocol: &protocol.Protocol_None{},
	}

	t.Log(reflect.TypeOf(p.GetProtocol()) == reflect.TypeOf(&protocol.Protocol_None{}))
}
