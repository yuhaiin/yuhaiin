// +build windows

package config

import (
	"io/ioutil"
	"os"
	"path"
	"strings"
)

func GetEnvPath(binName string) (filePath string) {
	for _, p := range strings.Split(os.ExpandEnv("$PATH"), ";") {
		files, _ := ioutil.ReadDir(p)
		for _, file := range files {
			if file.IsDir() {
				continue
			} else {
				if file.Name() == binName+".exe" {
					return path.Join(p, file.Name())
				}
			}
		}
	}
	return ""
}
