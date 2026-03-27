package config

type LogLevel int32

const (
	LogLevelVerbose LogLevel = 0
	LogLevelDebug   LogLevel = 1
	LogLevelInfo    LogLevel = 2
	LogLevelWarning LogLevel = 3
	LogLevelError   LogLevel = 4
	LogLevelFatal   LogLevel = 5
)

type Logcat struct {
	Level              LogLevel `json:"level"`
	Save               bool     `json:"save"`
	IgnoreTimeoutError bool     `json:"ignore_timeout_error"`
	IgnoreDnsError     bool     `json:"ignore_dns_error"`
}
