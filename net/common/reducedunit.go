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
		byte, unit = byte/1024, KB // KB
		if byte > 1024 {
			byte, unit = byte/1024, MB // MB
			if byte > 1024 {
				byte, unit = byte/1024, GB //GB
				if byte > 1024 {
					byte, unit = byte/1024, TB //TB
					if byte > 1024 {
						byte, unit = byte/1024, PB //PB
					}
				}
			}
		}
	}
	return byte, unit
}

func ReducedUnit2(byte float64) (result string) {
	unit := B2
	if byte > 1024 {
		byte, unit = byte/1024, KB2 // KB
		if byte > 1024 {
			byte, unit = byte/1024, MB2 // MB
			if byte > 1024 {
				byte, unit = byte/1024, GB2 //GB
				if byte > 1024 {
					byte, unit = byte/1024, TB2 //TB
					if byte > 1024 {
						byte, unit = byte/1024, PB2 //PB
					}
				}
			}
		}
	}
	return fmt.Sprintf("%.2f%s", byte, unit)
}
