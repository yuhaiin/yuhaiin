package log

import "log/slog"

func (l LogLevel) SLogLevel() slog.Level {
	switch l {
	case LogLevel_debug, LogLevel_verbose:
		return slog.LevelDebug
	case LogLevel_info:
		return slog.LevelInfo
	case LogLevel_warning:
		return slog.LevelWarn
	case LogLevel_error, LogLevel_fatal:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
