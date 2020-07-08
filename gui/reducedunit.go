package gui

import "fmt"

type Unit int

var (
	B   Unit = 0
	KB  Unit = 1
	MB  Unit = 2
	GB  Unit = 3
	TB  Unit = 4
	PB  Unit = 5
	B2       = "B"
	KB2      = "KB"
	MB2      = "MB"
	GB2      = "GB"
	TB2      = "TB"
	PB2      = "PB"
)

func ReducedUnit(byte float64) (result float64, unit Unit) {
	if byte > 1125899906842624 {
		return byte / 1125899906842624, PB //PB
	}
	if byte > 1099511627776 {
		return byte / 1099511627776, TB //TB
	}
	if byte > 1073741824 {
		return byte / 1073741824, GB //GB
	}
	if byte > 1048576 {
		return byte / 1048576, MB //MB
	}
	if byte > 1024 {
		return byte / 1024, KB //KB
	}
	return byte, B //B
}

func ReducedUnitStr(byte float64) (result string) {
	if byte > 1125899906842624 {
		return fmt.Sprintf("%.2f%s", byte/1125899906842624, PB2) //PB
	}
	if byte > 1099511627776 {
		return fmt.Sprintf("%.2f%s", byte/1099511627776, TB2) //TB
	}
	if byte > 1073741824 {
		return fmt.Sprintf("%.2f%s", byte/1073741824, GB2) //GB
	}
	if byte > 1048576 {
		return fmt.Sprintf("%.2f%s", byte/1048576, MB2) //MB
	}
	if byte > 1024 {
		return fmt.Sprintf("%.2f%s", byte/1024, KB2) //KB
	}
	return fmt.Sprintf("%.2f%s", byte, B2) //B
}
