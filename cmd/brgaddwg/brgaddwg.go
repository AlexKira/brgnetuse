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
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/AlexKira/brgnetuse/internal/help"
	"github.com/AlexKira/brgnetuse/internal/middleware"
	"github.com/AlexKira/brgnetuse/src/add"
)

const Env_Wg_Process_Forenground string = "WG_PROCESS_FOREGROUND"

// Main entry point.
func main() {

	if len(os.Args) < 2 || os.Args[1] == help.HelpFlag {
		help.BridgeAddWgHelp()
		return
	}

	var device add.WgLoggerStructure
	var pathLogDir string
	var loggingMap = map[string]int{
		help.LogInfoFlag:  middleware.LogInfo,
		help.LogErrorFlag: middleware.LogError,
	}

	for indx := 1; indx < len(os.Args); indx++ {

		if os.Args[indx] == help.WgInterfaceFlag {
			indx++
			if indx < len(os.Args) {
				device.InterfaceName = help.WgInterfaceNameValid(
					help.WgInterfaceFlag,
					os.Args[indx],
				)

				indx++
				if indx < len(os.Args) {
					if os.Args[indx] == help.PathLogDirFlag {

						indx++
						if indx < len(os.Args) {
							pathLogDir = help.PathLogDirValid(
								help.PathLogDirFlag,
								os.Args[indx],
							)

							indx++
							if indx < len(os.Args) {
								isLogLevel := loggingMap[os.Args[indx]]
								if isLogLevel == 0 {
									help.ErrorExitMessage(
										os.Args[indx],
										"error: logging level not found",
									)
									os.Exit(help.ExitSetupFailed)
								}
								device.LoggerName = "brgaddwg"
								device.LogLevel = isLogLevel

								indx++
								if indx < len(os.Args) {
									if os.Args[indx] == help.LogTypeFlag {
										device.LoggingJSON = true
									}
								}

							} else {
								help.ErrorExitMessage(
									help.PathLogDirFlag,
									fmt.Sprintf(
										"error: argument passed incorrectly, "+
											"example: '%s wg0 %s %s %s'",
										help.WgInterfaceFlag,
										help.PathLogDirFlag,
										pathLogDir,
										help.LogErrorFlag,
									),
								)
								os.Exit(help.ExitSetupFailed)
							}

						} else {
							help.ErrorExitMessage(
								help.PathLogDirFlag,
								fmt.Sprintf(
									"error: argument passed incorrectly, "+
										"example: '%s wg0 %s /var/log %s'",
									help.WgInterfaceFlag,
									help.PathLogDirFlag,
									help.LogErrorFlag,
								),
							)
							os.Exit(help.ExitSetupFailed)
						}
					} else {
						indx--
					}
				}

			} else {
				help.ErrorExitMessage(
					help.WgInterfaceFlag,
					fmt.Sprintf(
						"error: invalid argument passed, pass '%s', "+
							"followed by a valid WireGuard interface name "+
							"(e.g. '%s wg0', etc.)",
						help.WgInterfaceFlag,
						help.WgInterfaceFlag,
					),
				)
				os.Exit(help.ExitSetupFailed)
			}

		} else {
			help.ErrorExitMessage(
				os.Args[len(os.Args)-1],
				help.DefaultErrorMessage,
			)
			os.Exit(help.ExitSetupFailed)
		}
	}

	// Checking a running background process.
	if os.Getenv(Env_Wg_Process_Forenground) == "1" {
		if err := device.NewDevice(); err != nil {
			help.ErrorExitMessage("", err.Error())
			os.Exit(help.ExitSetupFailed)
		}
		return
	}

	// First run in background process.
	env := os.Environ()
	env = append(env, fmt.Sprintf("%s=1", Env_Wg_Process_Forenground))

	newSliceArgs := os.Args[1:]
	cmd := exec.Command(os.Args[0], newSliceArgs...)
	cmd.Env = env

	if pathLogDir != "" {
		openFile, err := os.OpenFile(
			fmt.Sprintf("%s/%s.log", pathLogDir, device.InterfaceName),
			os.O_CREATE|os.O_WRONLY|os.O_APPEND,
			0666,
		)
		if err != nil {
			help.ErrorExitMessage(
				"",
				fmt.Sprintf("error: failed to create logfile, %v", err),
			)
			os.Exit(help.ExitSetupFailed)
		}
		cmd.Stdout = openFile
		cmd.Stderr = openFile
		defer openFile.Close()
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	err := cmd.Start()
	if err != nil {
		help.ErrorExitMessage(
			"",
			fmt.Sprintf("error: failed starting background process, %v", err),
		)
		os.Exit(help.ExitSetupFailed)
	}
}
