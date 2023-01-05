package bypass

import (
	"bytes"
	"strings"
)

type ModeEnum interface {
	Mode() Mode
	Unknown() bool
	GetTag() string
}

func (m Mode) Mode() Mode { return m }
func (m Mode) Unknown() bool {
	_, ok := Mode_name[int32(m)]
	return !ok
}

func (Mode) GetTag() string { return "" }

func (m *ModeConfig) Unknown() bool { return m.Mode.Unknown() }

func (f *ModeConfig) StoreKV(fs [][]byte) {
	for _, x := range fs {
		i := bytes.IndexByte(x, '=')
		if i == -1 {
			continue
		}

		key := strings.ToLower(string(x[:i]))

		if key == "tag" {
			f.Tag = strings.ToLower(string(x[i+1:]))
		}
	}
}

type Tag string

func (f Tag) GetTag() string { return string(f) }
func (Tag) Mode() Mode       { return Mode_proxy }
func (Tag) Unknown() bool    { return false }
