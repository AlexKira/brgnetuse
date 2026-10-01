//go:build !windows

/*
The brgaddwg utility is designed to add WireGuard network interfaces.

Features:
- Configures a WireGuard network interface.
- Enables and disables logging. The level can be: Debug or Error.
- Provides two types of logging: String or JSON.
- Creates a log file, based on the interface name.

This utility was developed based on:
- https://github.com/WireGuard/wireguard-go/tree/master

For detailed information on AmneziaWG, refer to:
- https://www.wireguard.com
*/

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/AlexKira/brgnetuse/internal/help"
	"github.com/AlexKira/brgnetuse/internal/middleware"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

const Version = "3.01.202610001"
const UtilityName = " brgaddwg"

// Main entry point.
func main() {

	if len(os.Args) < 2 || os.Args[1] == help.HelpFlag {
		help.BridgeAddHelp(UtilityName, "wg100", false)
		return
	}

	if os.Args[1] == help.VersionFlag {
		fmt.Printf("v.%s\n", Version)
		return
	}

	wg, err := ParseArgs(os.Args)
	if err != nil {
		help.ErrorExitMessage(
			wg.CurrentFlag,
			err.Error(),
		)

		os.Exit(help.ExitSetupFailed)
	}

	if err := Execute(os.Args, wg); err != nil {
		help.ErrorExitMessage("", err.Error())

		os.Exit(help.ExitSetupFailed)
	}
}

// Function parses command-line arguments into a WgDebive struct,
// validating flags and their values, and returns errors for invalid input.
func ParseArgs(args []string) (WgDebive, error) {

	var wg WgDebive
	var loggingMap = map[string]int{
		help.LogInfoFlag:  middleware.LogInfo,
		help.LogErrorFlag: middleware.LogError,
	}

	for indx := 1; indx < len(args); indx++ {

		switch os.Args[indx] {
		case help.WgInterfaceFlag:
			indx++
			if indx < len(os.Args) {
				wg.InterfaceName = help.WgInterfaceNameValid(
					help.WgInterfaceFlag,
					os.Args[indx],
				)
			} else {
				wg.CurrentFlag = help.WgInterfaceFlag
				return wg, fmt.Errorf(
					"error: invalid argument passed, pass '%s', "+
						"followed by a valid WireGuard interface name "+
						"(e.g. '%s wg0', etc.)",
					help.WgInterfaceFlag,
					help.WgInterfaceFlag,
				)
			}
		case help.MTUFlag:
			indx++
			if indx < len(os.Args) {
				mtu, err := strconv.Atoi(os.Args[indx])
				if err != nil {
					return wg, fmt.Errorf(
						"error: invalid MTU number format: '%s'",
						os.Args[indx],
					)
				}

				if mtu < 500 || mtu > 1500 {
					wg.CurrentFlag = help.MTUFlag
					return wg, fmt.Errorf(
						"error: MTU value %d is out of valid range (500-1500)",
						mtu,
					)
				}

				wg.MTU = mtu

			} else {
				wg.CurrentFlag = help.MTUFlag
				return wg, errors.New(
					"error: please provide a valid MTU value",
				)
			}

		case help.PathLogDirFlag:
			if os.Args[indx] == help.PathLogDirFlag {
				indx++
				if indx < len(os.Args) {
					wg.PathLogDir = help.PathLogDirValid(
						help.PathLogDirFlag,
						os.Args[indx],
					)

					indx++
					if indx < len(os.Args) {
						isLogLevel := loggingMap[os.Args[indx]]
						if isLogLevel == 0 {
							wg.CurrentFlag = help.PathLogDirFlag

							return wg, errors.New(
								"error: logging level not found")
						}

						wg.LoggerName = UtilityName
						wg.LogLevel = isLogLevel

						indx++
						if indx < len(os.Args) {
							if os.Args[indx] == help.LogTypeFlag {
								wg.LoggingJSON = true
							} else {
								wg.CurrentFlag = help.LogTypeFlag
								return wg, errors.New(
									"error: logging type is missing",
								)
							}
						}
					}
				} else {
					wg.CurrentFlag = help.PathLogDirFlag
					return wg, errors.New(
						"error: please provide the path to the log folder",
					)
				}
			}
		default:
			wg.CurrentFlag = os.Args[indx]
			return wg, errors.New(help.DefaultErrorMessage)
		}
	}

	return wg, nil
}

// Function starts the WireGuard process with given arguments and configuration,
// optionally redirecting output to a log file and managing background execution.
func Execute(args []string, wg WgDebive) error {

	// Checking a running background process.
	if os.Getenv(help.Env_Field_Foreground) == "1" {
		if err := wg.NewDevice(); err != nil {
			return err
		}

		os.Exit(0)
	}

	// First run in background process.
	env := os.Environ()
	env = append(
		env,
		fmt.Sprintf("%s=1", help.Env_Field_Foreground),
		fmt.Sprintf("%s=%s", help.Env_Field_Tag, wg.InterfaceName),
	)

	newSliceArgs := args[1:]
	cmd := exec.Command(args[0], newSliceArgs...)
	cmd.Env = env

	if wg.PathLogDir != "" {
		openFile, err := os.OpenFile(
			fmt.Sprintf("%s/%s.log", wg.PathLogDir, wg.InterfaceName),
			os.O_CREATE|os.O_WRONLY|os.O_APPEND,
			0666,
		)

		if err != nil {
			return fmt.Errorf("error: failed to create logfile, %v", err)
		}

		cmd.Stdout = openFile
		cmd.Stderr = openFile

		defer openFile.Close()
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("error: failed starting background process, %v", err)
	}

	return nil
}

// WgDebive represents the WireGuard-Go device's configuration and operational parameters.
// It includes interface details, logging settings, and argument parsing context.
type WgDebive struct {
	InterfaceName string // WireGuard interface name.
	LoggerName    string // Logger name.
	LogLevel      int    // Logging level (0-NULL, 1-ERROR, 2-DEBUG).
	LoggingJSON   bool   // Flag indicating whether to use JSON format for logging.
	MTU           int

	PathLogDir  string
	CurrentFlag string
}

// NewDevice sets up and starts a new WireGuard-Go interface.
// It initializes the logger, TUN device, UAPI socket,
// and manages the device lifecycle.
func (p *WgDebive) NewDevice() error {

	var logger *device.Logger

	// Configure logger: choose between JSON (via middleware) or plain text.
	// No type conversion is needed here, as middleware returns the original
	// WireGuard device.Logger type.
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

	if p.MTU == 0 {
		p.MTU = device.DefaultMTU
	}

	// Open TUN device (or use supplied fd)
	tdev, err := tun.CreateTUN(p.InterfaceName, p.MTU)
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
