//+build debug

package microlog

import "fmt"

func Debug(a ...interface{}) {
	fmt.Println(a...)
}
