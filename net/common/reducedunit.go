package common

import "fmt"

var (
	B   = 0
	KB  = 1
	MB  = 2
	GB  = 3
	TB  = 4
	PB  = 5
	B2  = "B"
	KB2 = "KB"
	MB2 = "MB"
	GB2 = "GB"
	TB2 = "TB"
	PB2 = "PB"
)

func ReducedUnit(byte float64) (result float64, unit int) {
	unit = B
	if byte > 1024 {
		unit = KB //KB
		if byte > 1048576 {
			unit = MB // MB
			if byte > 1073741824 {
				unit = GB //GB
				if byte > 1099511627776 {
					unit = TB //TB
					if byte > 1125899906842624 {
						unit = PB //PB
					}
				}
			}
		}
	}
	switch unit {
	case KB:
		byte /= 1024
	case MB:
		byte /= 1048576
	case GB:
		byte /= 1073741824
	case TB:
		byte /= 1099511627776
	case PB:
		byte /= 1125899906842624
	}
	return byte, unit
}

func ReducedUnit2(byte float64) (result string) {
	unit := B2
	if byte > 1024 {
		unit = KB2 //KB
		if byte > 1048576 {
			unit = MB2 // MB
			if byte > 1073741824 {
				unit = GB2 //GB
				if byte > 1099511627776 {
					unit = TB2 //TB
					if byte > 1125899906842624 {
						unit = PB2 //PB
					}
				}
			}
		}
	}
	switch unit {
	case KB2:
		byte /= 1024
	case MB2:
		byte /= 1048576
	case GB2:
		byte /= 1073741824
	case TB2:
		byte /= 1099511627776
	case PB2:
		byte /= 1125899906842624
	}
	return fmt.Sprintf("%.2f%s", byte, unit)
}
