//go:build !windows

/*
The brgaddwg utility is designed to add WireGuard network interfaces.

Features:
- Configures a WireGuard network interface.
- Enables and disables logging. The level can be: Debug or Error.
- Provides two types of logging: String or JSON.
- Creates a log file, based on the interface name.

This utility was developed based on:
https://github.com/WireGuard/wireguard-go/tree/master.
*/

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"github.com/AlexKira/brgnetuse/internal/help"
	"github.com/AlexKira/brgnetuse/internal/middleware"
	"github.com/AlexKira/brgnetuse/src/add"
)

// WgDebive represents the WireGuard device configuration and related operational parameters.
// It holds parsed information necessary to set up and manage a WireGuard interface,
// as well as details for logging and tracking the current argument being processed.
type WgDebive struct {
	Device      add.WgStructure
	PathLogDir  string
	CurrentFlag string
}

// Main entry point.
func main() {

	if len(os.Args) < 2 || os.Args[1] == help.HelpFlag {
		help.BridgeAddWgHelp()
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

	if err := Execute(os.Args, wg, "WG_PROCESS_FOREGROUND"); err != nil {
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
				wg.Device.InterfaceName = help.WgInterfaceNameValid(
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

				wg.Device.MTU = mtu

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

						wg.Device.LoggerName = "brgaddwg"
						wg.Device.LogLevel = isLogLevel

						indx++
						if indx < len(os.Args) {
							if os.Args[indx] == help.LogTypeFlag {
								wg.Device.LoggingJSON = true
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
func Execute(args []string, wg WgDebive, env_proc_name string) error {

	// Checking a running background process.
	if os.Getenv(env_proc_name) == "1" {
		if err := wg.Device.NewDevice(); err != nil {
			return err
		}

		os.Exit(0)
	}

	// First run in background process.
	env := os.Environ()
	env = append(
		env,
		fmt.Sprintf("%s=1", env_proc_name),
	)

	newSliceArgs := args[1:]
	cmd := exec.Command(args[0], newSliceArgs...)
	cmd.Env = env

	if wg.PathLogDir != "" {
		openFile, err := os.OpenFile(
			fmt.Sprintf("%s/%s.log", wg.PathLogDir, wg.Device.InterfaceName),
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
