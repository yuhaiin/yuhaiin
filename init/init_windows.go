// +build windows

package ssrinit

import (
	"os"
)

// GetConfigAndSQLPath <-- get the config path
func GetConfigAndSQLPath() (configPath string) {
	return os.Getenv("USERPROFILE") + "\\Documents\\SSRSub"
}
