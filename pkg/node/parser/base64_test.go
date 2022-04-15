package parser

import "testing"

func TestBase64DStr(t *testing.T) {
	str := "eyJob3N0IjoiIiwicGF0aCI6IiIsInRscyI6IiIsInZlcmlmeV9jZXJ0Ijp0cnVl" +
		"LCJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjowLCJhaWQiOjIsIm5ldCI6InRjcCIsInR" +
		"5cGUiOiJub25lIiwidiI6IjIiLCJwcyI6Im5hbWUiLCJpZCI6ImNjY2MtY2NjYy1kZGR" +
		"kLWFhYS00NmExYWFhYWFhIiwiY2xhc3MiOjF9Cg"
	t.Log(DecodeUrlBase64(str))
}
