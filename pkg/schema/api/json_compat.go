package api

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/schema/statistic"
)

func (x *ChangePriorityRequestChangePriorityOperate) UnmarshalJSON(data []byte) error {
	var n int32
	if err := json.Unmarshal(data, &n); err == nil {
		*x = ChangePriorityRequestChangePriorityOperate(n)
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch strings.ToLower(strings.ReplaceAll(s, "_", "")) {
	case "exchange", "changepriorityrequestexchange", "0":
		*x = ChangePriorityRequest_Exchange
	case "insertbefore", "changepriorityrequestinsertbefore", "1":
		*x = ChangePriorityRequest_InsertBefore
	case "insertafter", "changepriorityrequestinsertafter", "2":
		*x = ChangePriorityRequest_InsertAfter
	default:
		return fmt.Errorf("unknown change priority operate %q", s)
	}
	return nil
}

func (x *Counter) UnmarshalJSON(data []byte) error {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	x.Download = uint64FromJSON(raw, "download")
	x.Upload = uint64FromJSON(raw, "upload")
	return nil
}

func (x *TotalFlow) UnmarshalJSON(data []byte) error {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	x.Download = uint64FromJSON(raw, "download")
	x.Upload = uint64FromJSON(raw, "upload")
	if v := rawValue(raw, "counters"); len(v) != 0 && string(v) != "null" {
		counters, err := counterMapFromJSON(v)
		if err != nil {
			return fmt.Errorf("counters: %w", err)
		}
		x.Counters = counters
	}
	return nil
}

func (x *NotifyRemoveConnections) UnmarshalJSON(data []byte) error {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	ids, err := uint64SliceFromJSON(rawValue(raw, "ids"))
	if err != nil {
		return fmt.Errorf("ids: %w", err)
	}
	x.Ids = ids
	return nil
}

func (x *BlockHistory) UnmarshalJSON(data []byte) error {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	x.Protocol = stringFromJSON(raw, "protocol")
	x.Host = stringFromJSON(raw, "host")
	x.Process = stringFromJSON(raw, "process")
	x.BlockCount = uint64FromJSON(raw, "block_count", "blockCount")
	if v := rawValue(raw, "time"); len(v) != 0 && string(v) != "null" {
		if err := json.Unmarshal(v, &x.Time); err != nil {
			return fmt.Errorf("time: %w", err)
		}
	}
	return nil
}

func (x *FailedHistory) UnmarshalJSON(data []byte) error {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if v := rawValue(raw, "protocol"); len(v) != 0 && string(v) != "null" {
		if err := json.Unmarshal(v, &x.Protocol); err != nil {
			return fmt.Errorf("protocol: %w", err)
		}
	}
	x.Host = stringFromJSON(raw, "host")
	x.Error = stringFromJSON(raw, "error")
	x.Process = stringFromJSON(raw, "process")
	x.FailedCount = uint64FromJSON(raw, "failed_count", "failedCount")
	if v := rawValue(raw, "time"); len(v) != 0 && string(v) != "null" {
		if err := json.Unmarshal(v, &x.Time); err != nil {
			return fmt.Errorf("time: %w", err)
		}
	}
	return nil
}

func (x *AllHistory) UnmarshalJSON(data []byte) error {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if v := rawValue(raw, "connection"); len(v) != 0 && string(v) != "null" {
		x.Connection = &statistic.Connection{}
		if err := json.Unmarshal(v, x.Connection); err != nil {
			return fmt.Errorf("connection: %w", err)
		}
	}
	x.Count = uint64FromJSON(raw, "count")
	if v := rawValue(raw, "time"); len(v) != 0 && string(v) != "null" {
		if err := json.Unmarshal(v, &x.Time); err != nil {
			return fmt.Errorf("time: %w", err)
		}
	}
	return nil
}

func counterMapFromJSON(data jsontext.Value) (map[uint64]Counter, error) {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	out := make(map[uint64]Counter, len(raw))
	for key, value := range raw {
		id, err := strconv.ParseUint(key, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", key, err)
		}
		var counter Counter
		if err := json.Unmarshal(value, &counter); err != nil {
			return nil, fmt.Errorf("%q: %w", key, err)
		}
		out[id] = counter
	}
	return out, nil
}

func uint64SliceFromJSON(data jsontext.Value) ([]uint64, error) {
	if len(data) == 0 || string(data) == "null" {
		return nil, nil
	}
	var values []jsontext.Value
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, err
	}
	out := make([]uint64, 0, len(values))
	for i, value := range values {
		n, err := uint64ValueFromJSON(value)
		if err != nil {
			return nil, fmt.Errorf("%d: %w", i, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func uint64ValueFromJSON(data jsontext.Value) (uint64, error) {
	var n uint64
	if err := json.Unmarshal(data, &n); err == nil {
		return n, nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return 0, err
	}
	return strconv.ParseUint(s, 10, 64)
}
