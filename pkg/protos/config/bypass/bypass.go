package bypass

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
