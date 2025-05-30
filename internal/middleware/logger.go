// Package for logger processing.
package middleware

import (
	"fmt"
	"log/slog"
	"os"

	"golang.zx2c4.com/wireguard/device"
)

const (
	LogNull  int = device.LogLevelSilent
	LogError int = device.LogLevelError
	LogInfo  int = device.LogLevelVerbose
)

// Basic Fields for JsonLogger Structure.
type LoggingStruct struct {
	LogLevel   int
	FuncName   string
	Pid        int
	MainThread int
}

// Function to convert logger string format to JSON.
func (param *LoggingStruct) WgJsonLoggerMiddleware(interfaceName string) *device.Logger {

	loglevel := param.LogLevel
	cfg := &slog.HandlerOptions{Level: slog.LevelDebug}
	jsonHandler := slog.NewJSONHandler(os.Stdout, cfg)

	logger := slog.New(jsonHandler).With(
		slog.String("func", param.FuncName),
		slog.Int("pid", param.Pid),
		slog.Int("main_thread", param.MainThread),
		slog.String("interface", interfaceName),
	)

	newDeviceLogger := &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf:   device.DiscardLogf,
	}

	if loglevel >= device.LogLevelVerbose {
		newDeviceLogger.Verbosef = func(msg string, args ...any) {
			logger.Debug(fmt.Sprintf(msg, args...))
		}
	}
	if loglevel >= device.LogLevelError {
		newDeviceLogger.Errorf = func(msg string, args ...any) {
			logger.Error(fmt.Sprintf(msg, args...))
		}
	}
	return newDeviceLogger
}
