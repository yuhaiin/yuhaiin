package unit

// Unit .
type Unit int

const (
	//B .
	B Unit = 0
	//KB .
	KB Unit = 1
	//MB .
	MB Unit = 2
	//GB .
	GB Unit = 3
	//TB .
	TB Unit = 4
	//PB .
	PB Unit = 5
)

func (u Unit) String() string {
	switch u {
	case B:
		return "B"
	case KB:
		return "KB"
	case MB:
		return "MB"
	case GB:
		return "GB"
	case TB:
		return "TB"
	case PB:
		return "PB"
	default:
		return "B"
	}
}

// ReducedUnit .
func ReducedUnit(byte float64) (result float64, unit Unit) {
	if byte >= 1125899906842624 {
		return byte / 1125899906842624, PB //PB
	}
	if byte >= 1099511627776 {
		return byte / 1099511627776, TB //TB
	}
	if byte >= 1073741824 {
		return byte / 1073741824, GB //GB
	}
	if byte >= 1048576 {
		return byte / 1048576, MB //MB
	}
	if byte >= 1024 {
		return byte / 1024, KB //KB
	}
	return byte, B //B
}
