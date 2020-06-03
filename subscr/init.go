package subscr

import (
	"log"

	"github.com/Asutorufa/yuhaiin/config"
)

func init() {
	//cycle import,not allow
	if !config.PathExists(config.Path + "/node.json") {
		if err := InitJSON(); err != nil {
			log.Println(err)
			return
		}
	}
}
