package api

type Empty struct{}

type StringValue struct {
	Value string `json:"value,omitempty"`
}

func String(value string) *StringValue {
	return &StringValue{Value: value}
}

func (x *StringValue) GetValue() string {
	if x == nil {
		return ""
	}
	return x.Value
}
