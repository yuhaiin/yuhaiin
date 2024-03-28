package bypass

import (
	"bytes"
	"strings"
)

type ModeEnum interface {
	Mode() Mode
	Unknown() bool
	GetTag() string
	GetResolveStrategy() ResolveStrategy
}

func (m Mode) Mode() Mode { return m }
func (m Mode) Unknown() bool {
	_, ok := Mode_name[int32(m)]
	return !ok
}

func (Mode) GetTag() string                      { return "" }
func (Mode) GetResolveStrategy() ResolveStrategy { return ResolveStrategy_default }

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

		if key == "resolve_strategy" {
			f.ResolveStrategy = ResolveStrategy(ResolveStrategy_value[strings.ToLower(string(x[i+1:]))])
		}
	}
}

func (f *ModeConfig) ToModeEnum() ModeEnum {
	if f.ResolveStrategy == ResolveStrategy_default && f.Tag == "" {
		return f.Mode
	}

	return &modeConfig{f.Mode, f.Tag, f.ResolveStrategy}
}

type modeConfig struct {
	mode            Mode
	Tag             string
	ResolveStrategy ResolveStrategy
}

func (m modeConfig) Mode() Mode                          { return m.mode }
func (m modeConfig) GetTag() string                      { return m.Tag }
func (modeConfig) Unknown() bool                         { return false }
func (m modeConfig) GetResolveStrategy() ResolveStrategy { return m.ResolveStrategy }
