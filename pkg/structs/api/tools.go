package api

import (
	"github.com/Asutorufa/yuhaiin/pkg/structs/tools"
)

type Tools struct {
	GetInterface Service[struct{}, tools.Interfaces]
	Licenses     Service[struct{}, tools.Licenses]
	Log          Service[struct{}, <-chan tools.Log]
	LogV2        Service[struct{}, <-chan tools.Logv2]
}
