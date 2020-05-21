// +build windows

package process

import "github.com/Asutorufa/yuhaiin/config"

func extendsProxyInit(conFig *config.Setting)          {}
func extendsUpdateListen(conFig *config.Setting) error { return nil }
