/*
Package add provides functionality for creating and configuring WireGuard interfaces.

This package contains functions and structures necessary for initializing and running
a WireGuard device on non-Windows systems. It provides an API for creating a TUN device,
a UAPI socket, configuring logging, and managing the WireGuard device.

The package utilizes the WireGuard-go libraries for interacting with WireGuard and
offers flexible logging configuration options, including JSON format support.

**Key features:**

- Creating and configuring WireGuard interfaces.
- Configuring logging with JSON format support.
- Managing the WireGuard device via the UAPI socket.
- Signal handling for graceful shutdown.

**Developed based on:**
https://github.com/WireGuard/wireguard-go/tree/master.
*/
package add

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/AlexKira/brgnetuse/internal/middleware"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

const Version string = "0.0.20230223"

// WgLoggerStructure represents the configuration for the WireGuard logger.
type WgLoggerStructure struct {
	InterfaceName string // WireGuard interface name.
	LoggerName    string // Logger name.
	LogLevel      int    // Logging level (0-NULL, 1-ERROR, 2-DEBUG).
	LoggingJSON   bool   // Flag indicating whether to use JSON format for logging.
}

// Method creates and configures a new WireGuard interface.
//
// **Usage examples:**
//
// ```go
//
//	device := add.WgLoggerStructure{
//		LoggerName:    "brgaddwg",
//		InterfaceName: "wg0",
//		LogLevel:      2,
//		LoggingJSON:   false,
//	}
//
//	err := device.NewDevice()
//	if err != nil {
//	    // Handle error
//	}
//
// ```
func (p *WgLoggerStructure) NewDevice() error {

	var logger *device.Logger

	// Define logging type (JSON or plain text).
	if p.LoggingJSON {
		logging := middleware.LoggingStruct{
			LogLevel:   p.LogLevel,
			FuncName:   p.LoggerName,
			Pid:        os.Getpid(),
			MainThread: syscall.Gettid(),
		}
		logger = logging.WgJsonLoggerMiddleware(p.InterfaceName)
	} else {
		logger = device.NewLogger(
			p.LogLevel,
			fmt.Sprintf(
				"[%s] %s %d %d ",
				p.InterfaceName,
				p.LoggerName,
				os.Getpid(),
				syscall.Gettid(),
			),
		)
	}

	// Open TUN device (or use supplied fd)
	tdev, err := tun.CreateTUN(p.InterfaceName, device.DefaultMTU)
	if err == nil {
		realInterfaceName, err2 := tdev.Name()
		if err2 == nil {
			p.InterfaceName = realInterfaceName
		}
	}
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %v", err)
	}

	// Open UAPI file (or use supplied fd)
	fileUAPI, err := ipc.UAPIOpen(p.InterfaceName)
	if err != nil {
		return fmt.Errorf("uAPI listen error: %v", err)
	}

	// Device started.
	logger.Verbosef("Starting 'wireGuard-go' protocol version: %s", Version)

	device := device.NewDevice(
		tdev,
		conn.NewStdNetBind(),
		logger,
	)

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	uapi, err := ipc.UAPIListen(p.InterfaceName, fileUAPI)
	if err != nil {
		return fmt.Errorf("failed to listen on uapi socket: %v", err)
	}

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go device.IpcHandle(conn)
		}
	}()

	logger.Verbosef("UAPI listener started")

	// Wait for program to terminate
	signal.Notify(term, unix.SIGTERM)
	signal.Notify(term, os.Interrupt)

	select {
	case <-term:
	case <-errs:
	case <-device.Wait():
	}

	// Clean
	uapi.Close()
	device.Close()

	logger.Verbosef("Shutting down")

	return nil
}
