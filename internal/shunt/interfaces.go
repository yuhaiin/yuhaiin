package shunt

import (
	_ "embed"
)

type MODE_MARK_KEY struct{}

func (MODE_MARK_KEY) String() string { return "MODE" }

//go:embed statics/bypass.gz
var BYPASS_DATA []byte

type ForceModeKey struct{}
