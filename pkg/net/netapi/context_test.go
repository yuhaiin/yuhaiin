package netapi

import (
	"fmt"
	"net"
	"reflect"
	"strconv"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestMap(t *testing.T) {
	testAddr, err := net.ResolveTCPAddr("tcp", "1.1.1.1:1")
	assert.NoError(t, err)

	ctx := &Context{
		DomainString:  "test ds",
		ModeReason:    "test mr",
		IPString:      "1.1.1.1",
		Source:        testAddr,
		Inbound:       testAddr,
		Destination:   testAddr,
		FakeIP:        testAddr,
		Hosts:         testAddr,
		Tag:           "test tag",
		Hash:          "test hash",
		Protocol:      "test protocol",
		Process:       "test process",
		ProcessPid:    1,
		ProcessUid:    1,
		TLSServerName: "test tls servername",
		HTTPHost:      "test http host",
		Component:     "test component",
		UDPMigrateID:  1,
		ForceMode:     bypass.Mode(1),
		SniffMode:     bypass.Mode(1),
		Mode:          bypass.Mode(1),
	}

	data := ctx.Map()
	for k, v := range ctx.MapTest() {
		assert.MustEqual(t, v, data[k])
	}
}

func (addr *Context) MapTest() map[string]string {
	values := reflect.ValueOf(*addr)
	types := values.Type()

	maps := make(map[string]string)

	for i := range values.NumField() {
		v, ok := toString(values.Field(i))
		if !ok || v == "" {
			continue
		}

		k := types.Field(i).Tag.Get("metrics")
		if k == "" || k == "-" {
			continue
		}

		maps[k] = v
	}

	return maps
}

func toString(t reflect.Value) (string, bool) {
	if !t.IsValid() {
		return "", false
	}

	switch t.Kind() {
	case reflect.String:
		return t.String(), true
	default:
		if t.CanInterface() {
			if z, ok := t.Interface().(fmt.Stringer); ok {
				return z.String(), true
			}
		}
	}

	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		integer := t.Int()
		if integer != 0 {
			return strconv.FormatInt(t.Int(), 10), true
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		uinteger := t.Uint()
		if uinteger != 0 {
			return strconv.FormatUint(t.Uint(), 10), true
		}
	}

	return "", false
}
