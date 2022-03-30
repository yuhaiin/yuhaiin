//go:build !nostatic
// +build !nostatic

package app

import _ "embed" //embed for bypass file

//go:embed yuhaiin.conf
var bypassData []byte
