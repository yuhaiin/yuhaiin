package process

import (
	"github.com/Asutorufa/yuhaiin/net/common"

	"github.com/Asutorufa/yuhaiin/config"
)

var (
	conFig, _ = config.SettingDecodeJSON()
)

func UpdateConFig() {
	conFig, _ = config.SettingDecodeJSON()
}

func processInit() error {
	//UpdateDNS(conFig.DnsServer)
	if err := UpdateMatch(); err != nil {
		return err
	}
	common.ForwardTarget = Forward
	//if err := UpdateListen(); err != nil {
	//	return err
	//}
	return ChangeNode()
}
