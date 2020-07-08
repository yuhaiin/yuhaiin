// +build windows

package config

import (
	"io/ioutil"
	"os"
	"strings"
)

var (
	Path = usr.HomeDir + pathSeparator + "AppData" + pathSeparator + "Roaming" + pathSeparator + "yuhaiin"
)

func GetEnvPath(binName string) (path string) {
	for _, p := range strings.Split(os.ExpandEnv("$PATH"), ";") {
		files, _ := ioutil.ReadDir(p)
		for _, file := range files {
			if file.IsDir() {
				continue
			} else {
				if file.Name() == binName+".exe" {
					return p + pathSeparator + file.Name()
				}
			}
		}
	}
	return ""
}
