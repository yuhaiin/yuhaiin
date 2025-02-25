//go:build !linux || android

package device

func (o *Opt) SkipMark()   {}
func (o *Opt) UnSkipMark() {}
