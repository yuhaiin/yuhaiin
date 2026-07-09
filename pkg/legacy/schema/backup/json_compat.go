package backup

import (
	json "encoding/json/v2"
	"fmt"
	"strconv"
)

func (x *RestoreOptionRestoreSource) UnmarshalJSON(data []byte) error {
	v, err := legacyEnum(data, RestoreOptionRestoreSource_value)
	if err != nil {
		return err
	}
	*x = RestoreOptionRestoreSource(v)
	return nil
}

func legacyEnum(data []byte, values map[string]int32) (int32, error) {
	var n int32
	if err := json.Unmarshal(data, &n); err == nil {
		return n, nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return 0, err
	}
	if v, ok := values[s]; ok {
		return v, nil
	}
	if n64, err := strconv.ParseInt(s, 10, 32); err == nil {
		return int32(n64), nil
	}
	return 0, fmt.Errorf("unknown enum value %q", s)
}
