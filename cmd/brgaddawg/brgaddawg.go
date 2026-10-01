//go:build !windows

/*
Package brgaddawg provides a utility to configure AmneziaWG network interfaces.

Key Features:
- Facilitates the creation and setup of AmneziaWG (obfuscated WireGuard) network interfaces.
- Offers configurable logging with 'Debug' or 'Error' levels.
- Supports both plain string and JSON log output formats.
- Generates a dedicated log file per interface, named after the interface.

This utility leverages components derived from:
- https://github.com/amnezia-vpn/amneziawg-go (AmneziaWG Go implementation v.0.0.20250522)

For detailed information on AmneziaWG, refer to:
- https://docs.amnezia.org/documentation/amnezia-wg
*/

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/AlexKira/brgnetuse/internal/help"
	"github.com/AlexKira/brgnetuse/internal/middleware"
	"github.com/AlexKira/brgnetuse/src/get"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/ipc"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"

	"golang.org/x/sys/unix"
)

const Version = "3.01.20261001"
const UtilityName = "brgaddawg"

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

// Main entry point.
func main() {

	if len(os.Args) < 2 || os.Args[1] == help.HelpFlag {
		help.BridgeAddHelp(UtilityName, "awg10", true)
		return
	}

	if os.Args[1] == help.VersionFlag {
		fmt.Printf("v.%s\n", Version)
		return
	}

	awg, err := ParseArgs(os.Args)
	if err != nil {
		help.ErrorExitMessage(
			awg.CurrentFlag,
			err.Error(),
		)

		os.Exit(help.ExitSetupFailed)
	}

	if err := Execute(os.Args, awg); err != nil {
		help.ErrorExitMessage("", err.Error())

		os.Exit(help.ExitSetupFailed)
	}
}

// Function parses command-line arguments into a WgDebive struct,
// validating flags and their values, and returns errors for invalid input.
func ParseArgs(args []string) (AwgDebive, error) {

	var awg AwgDebive
	var loggingMap = map[string]int{
		help.LogInfoFlag:  middleware.LogInfo,
		help.LogErrorFlag: middleware.LogError,
	}

	for indx := 1; indx < len(args); indx++ {

		switch os.Args[indx] {
		case help.WgInterfaceFlag:
			indx++
			if indx < len(os.Args) {
				awg.InterfaceName = help.WgInterfaceNameValid(
					help.WgInterfaceFlag,
					os.Args[indx],
				)
			} else {
				awg.CurrentFlag = help.WgInterfaceFlag
				return awg, fmt.Errorf(
					"error: invalid argument passed, pass '%s', "+
						"followed by a valid WireGuard interface name "+
						"(e.g. '%s awg0', etc.)",
					help.WgInterfaceFlag,
					help.WgInterfaceFlag,
				)
			}
		case help.MTUFlag:
			indx++
			if indx < len(os.Args) {
				mtu, err := strconv.Atoi(os.Args[indx])
				if err != nil {
					return awg, fmt.Errorf(
						"error: invalid MTU number format: '%s'",
						os.Args[indx],
					)
				}

				if mtu < 500 || mtu > 1500 {
					awg.CurrentFlag = help.MTUFlag
					return awg, fmt.Errorf(
						"error: MTU value %d is out of valid range (500-1500)",
						mtu,
					)
				}

				awg.MTU = mtu

			} else {
				awg.CurrentFlag = help.MTUFlag
				return awg, errors.New(
					"error: please provide a valid MTU value",
				)
			}

		case help.PathLogDirFlag:
			if os.Args[indx] == help.PathLogDirFlag {
				indx++
				if indx < len(os.Args) {
					awg.PathLogDir = help.PathLogDirValid(
						help.PathLogDirFlag,
						os.Args[indx],
					)

					indx++
					if indx < len(os.Args) {

						isLogLevel := loggingMap[os.Args[indx]]
						if isLogLevel == 0 {
							awg.CurrentFlag = help.PathLogDirFlag
							return awg, errors.New(
								"error: logging level not found")
						}

						awg.LoggerName = UtilityName
						awg.LogLevel = isLogLevel

						indx++
						if indx < len(os.Args) {

							if os.Args[indx] == help.LogTypeFlag {
								awg.LoggingJSON = true

							} else if json.Valid([]byte(os.Args[indx])) {
								awg.AwgJSON = os.Args[indx]
							} else {
								awg.CurrentFlag = help.LogTypeFlag
								return awg, errors.New(
									"error: logging type is missing",
								)
							}
						}
					}
				} else {
					awg.CurrentFlag = help.PathLogDirFlag
					return awg, errors.New(
						"error: please provide the path to the log folder",
					)
				}
			}
		default:

			if indx == len(os.Args[indx])-1 || json.Valid([]byte(os.Args[indx])) {
				awg.AwgJSON = os.Args[indx]
				continue
			}

			awg.CurrentFlag = os.Args[indx]
			return awg, errors.New(help.DefaultErrorMessage)
		}
	}

	return awg, nil
}

// Function starts the WireGuard process with given arguments and configuration,
// optionally redirecting output to a log file and managing background execution.
func Execute(args []string, awg AwgDebive) error {

	// Checking a running background process.
	if os.Getenv(help.Env_Field_Foreground) == "1" {
		if err := awg.NewDevice(); err != nil {
			return err
		}

		os.Exit(0)
	}

	// First run in background process.
	env := os.Environ()
	env = append(
		env,
		fmt.Sprintf("%s=1", help.Env_Field_Foreground),
		fmt.Sprintf("%s=%s", help.Env_Field_Tag, awg.InterfaceName),
	)

	newSliceArgs := args[1:]
	cmd := exec.Command(args[0], newSliceArgs...)
	cmd.Env = env

	if awg.PathLogDir != "" {
		openFile, err := os.OpenFile(
			fmt.Sprintf("%s/%s.log", awg.PathLogDir, awg.InterfaceName),
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

// AwgDebive represents the AmneziaWG device's configuration and operational parameters.
// It includes interface details, logging settings, and argument parsing context.
type AwgDebive struct {
	InterfaceName string // WireGuard interface name.
	LoggerName    string // Logger name.
	LogLevel      int    // Logging level (0-NULL, 1-ERROR, 2-DEBUG).
	LoggingJSON   bool   // Flag indicating whether to use JSON format for logging.
	MTU           int

	AwgJSON string

	PathLogDir  string
	CurrentFlag string
}

// Method sets up and starts a new AmneziaWG interface.
// It initializes the logger, TUN device, UAPI socket,
// and manages the device lifecycle.
func (p *AwgDebive) NewDevice() error {

	var logger *device.Logger

	uApiConfig, err := fmtUApiConfig(p.AwgJSON)
	if err != nil {
		return err
	}

	// Configure logger: choose between JSON (via middleware) or plain text.
	// Note: Type conversion `(*device.Logger)` is needed for middleware's output
	// as it returns an original WireGuard logger type.
	if p.LoggingJSON {
		logging := middleware.LoggingStruct{
			LogLevel:   p.LogLevel,
			FuncName:   p.LoggerName,
			Pid:        os.Getpid(),
			MainThread: syscall.Gettid(),
		}
		logger = (*device.Logger)(logging.WgJsonLoggerMiddleware(p.InterfaceName))
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
	logger.Verbosef("Starting 'amneziawg-go' protocol version: %s", Version)

	device := device.NewDevice(
		tdev,
		conn.NewStdNetBind(),
		logger,
	)

	device.IpcSet(uApiConfig)
	device.Up()

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

// Function returns a random number within the inclusive [min, max] range.
func randNum[T ~uint16 | ~uint32](min, max T) T {
	return min + T(rng.Uint32()%uint32(max-min+1))
}

// Function decodes a Base64-encoded 32-byte key and returns its hexadecimal representation.
func hexDecodedBase64(key, field string) (string, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf(
			"error: decoding Base64 %s: %v",
			field,
			err,
		)
	}

	if len(decodedBytes) != 32 {
		return "", fmt.Errorf(
			"error: invalid '%s' length: got %d bytes, want 32",
			field,
			len(decodedBytes),
		)
	}

	return hex.EncodeToString(decodedBytes), nil
}

// Function formats AmneziaWG JSON configuration into UAPI-compatible parameters.
func fmtUApiConfig(jsonConfig string) (string, error) {
	var params get.AwgObfuscateStructure

	if jsonConfig == "" {

		params = get.AwgObfuscateStructure{
			Jc:   randNum(uint16(5), uint16(20)),
			Jmin: randNum(uint16(20), uint16(100)),
			Jmax: randNum(uint16(100), uint16(200)),

			S1: randNum(uint16(12), uint16(100)),
			S2: randNum(uint16(13), uint16(100)),
			S3: randNum(uint16(14), uint16(100)),
			S4: randNum(uint16(15), uint16(100)),

			H1: fmt.Sprintf("%d", randNum(uint32(150000000), uint32(200000000))),
			H2: fmt.Sprintf("%d", randNum(uint32(250000000), uint32(300000000))),
			H3: fmt.Sprintf("%d", randNum(uint32(350000000), uint32(400000000))),
			H4: fmt.Sprintf("%d", randNum(uint32(450000000), uint32(500000000))),
		}

	} else {
		if err := json.Unmarshal([]byte(jsonConfig), &params); err != nil {
			return "", fmt.Errorf(
				"error: invalid AmneziaWG JSON: %v",
				err,
			)
		}

		if params.HeaderProtectionKey != "" {
			if params.S1 < 12 ||
				params.S2 < 12 ||
				params.S3 < 12 ||
				params.S4 < 12 {
				return "", fmt.Errorf(
					"error: S1-S4 must be greater than or equal to 12",
				)
			}

			hexHeaderProtectionKey, err := hexDecodedBase64(
				params.HeaderProtectionKey,
				"header_protection_key",
			)

			if err != nil {
				return "", err
			}

			params.HeaderProtectionKey = hexHeaderProtectionKey
		}

	}

	var b strings.Builder

	v := reflect.ValueOf(params)
	t := reflect.TypeOf(params)

	for i := 0; i < v.NumField(); i++ {
		name := t.Field(i).Tag.Get("json")
		value := v.Field(i)

		if value.IsZero() {
			continue
		}

		fmt.Fprintf(&b, "%s=%v\n", name, value.Interface())
	}

	return b.String(), nil

}
