package bypass

import (
	"bytes"
	"strings"
)

type ModeEnum interface {
	Mode() Mode
	Unknown() bool
	Value(string) (string, bool)
}

func (m Mode) Mode() Mode { return m }
func (m Mode) Unknown() bool {
	_, ok := Mode_name[int32(m)]
	return !ok
}

func (Mode) Value(string) (string, bool) { return "", false }

func (f *ModeConfig) Value(key string) (string, bool) {
	if f == nil || f.Fields == nil {
		return "", false
	}

	x, ok := f.Fields[key]
	return x, ok
}

func (m *ModeConfig) Unknown() bool { return m.Mode.Unknown() }

func (f *ModeConfig) StoreKV(fs [][]byte) {
	for _, x := range fs {
		i := bytes.IndexByte(x, '=')
		if i == -1 {
			continue
		}

		if f.Fields == nil {
			f.Fields = make(map[string]string)
		}

		f.Fields[strings.ToLower(string(x[:i]))] = strings.ToLower(string(x[i+1:]))
	}
}
