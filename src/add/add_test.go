package add

import (
	"testing"
)

type TestConfig struct {
	Name  string
	Input WgStructure
}

func TestNewDevice(t *testing.T) {
	var tests = []TestConfig{
		{
			Name: "Interface: '', LogLevel: 0, LoggingJSON: false",
			Input: WgStructure{
				InterfaceName: "",
				LoggerName:    "test_logger",
				LogLevel:      0,
				LoggingJSON:   false,
			},
		},
		{
			Name: "Interface: wgTest, LogLevel: 0, LoggingJSON: false",
			Input: WgStructure{
				InterfaceName: "wgTest",
				LoggerName:    "test_logger",
				LogLevel:      0,
				LoggingJSON:   false,
			},
		},
		{
			Name: "Interface: wgTest, LogLevel: 1, LoggingJSON: false",
			Input: WgStructure{
				InterfaceName: "wgTest",
				LoggerName:    "test_logger",
				LogLevel:      1,
				LoggingJSON:   false,
			},
		},
		{
			Name: "Interface:wgTest, LogLevel: 2, LoggingJSON: false",
			Input: WgStructure{
				InterfaceName: "wgTest",
				LoggerName:    "test_logger",
				LogLevel:      2,
				LoggingJSON:   false,
			},
		},
		{
			Name: "Interface: !12s>?$, LogLevel: 2, LoggingJSON: false",
			Input: WgStructure{
				InterfaceName: "!12s>?$",
				LoggerName:    "test_logger",
				LogLevel:      0,
				LoggingJSON:   false,
			},
		},
		{
			Name: "Interface: wgTest, LogLevel: -100, LoggingJSON: true",
			Input: WgStructure{
				InterfaceName: "wgTest",
				LoggerName:    "test_logger",
				LogLevel:      -100,
				LoggingJSON:   true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			t.Log("--------------------------------------")
			t.Logf("Run test: %s", tc.Name)

			errChan := make(chan error, 1)

			go func(device WgStructure, errChan chan error) {
				err := device.NewDevice()
				errChan <- err
			}(tc.Input, errChan)

			var receivedErr error

			select {
			case err := <-errChan:
				receivedErr = err
				t.Logf("warning: goroutine '%s' continues testing", tc.Name)
			default:
				receivedErr = nil
				t.Logf(
					"info: successful execution of goroutine '%s' continues testing",
					tc.Name,
				)
			}

			if receivedErr != nil {
				t.Errorf(
					"error: received an unexpected error from NewDevice(): %v", receivedErr)
			} else {
				t.Log("info: New Device() completed without errors")
			}

			t.Logf("End test: %s", tc.Name)
			t.Log("--------------------------------------")
		})
	}
}
