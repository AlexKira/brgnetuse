//go:build !windows

/*
The brgsetwg utility is designed to install and update the server's network rules.

Capabilities:
- Configure IP settings for network interfaces (IP addresses, subnet masks, etc.).
- Add or remove WireGuard peer configurations.
- Add or remove NAT and firewall rules (e.g., iptables rules).
- Enable or disable IPv4 and IPv6 forwarding.
- Modify or delete Base64-encoded private and public keys for WireGuard configurations and peers.
*/

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/AlexKira/brgnetuse/internal/help"
	"github.com/AlexKira/brgnetuse/internal/shell"
	"github.com/AlexKira/brgnetuse/src/get"
	"github.com/AlexKira/brgnetuse/src/set"
)

var DefaultErrorMessage string = fmt.Sprintf(
	"Arguments passed incorrectly. Ask for help: [%s]",
	help.HelpFlag,
)

// Structure for storing flags.
type ReceivedArgsStructure struct {
	InterfaceNameArray [2]string
	IpAddressArray     [2]string
	NatArray           [3]string
	ForwardIpvArray    [2]string
}

// Main entry point.
func main() {
	if len(os.Args) < 2 || os.Args[1] == help.HelpFlag {
		help.BridgeSetWgHelp()
		return
	}

	param := ReceivedArgsStructure{}
	for indx := 1; indx < len(os.Args); indx++ {
		switch os.Args[indx] {
		case help.WgInterfaceFlag:
			indx++
			if indx < len(os.Args) {
				indx = param.InterfaceArgsHandler(indx)
			} else {
				help.ErrorExitMessage(
					help.WgInterfaceFlag,
					fmt.Sprintf("Invalid argument passed. Pass [%s], "+
						"followed by a valid WireGuard interface name "+
						"(e.g. [%s wg0], [%s wg1], etc.)",
						help.WgInterfaceFlag,
						help.WgInterfaceFlag,
						help.WgInterfaceFlag,
					),
				)
				os.Exit(help.ExitSetupFailed)
			}
		case help.IpAddressFlag:
			indx++
			if indx < len(os.Args) {
				indx = param.IpAddressArgsHandler(indx)
			} else {
				help.ErrorExitMessage(
					help.IpAddressFlag,
					fmt.Sprintf("Invalid argument passed. Pass [%s], "+
						"followed by a valid ip address "+
						"(e.g. [%s wg0 %s 10.0.0.1/24 %s] etc.)",
						help.IpAddressFlag,
						help.WgInterfaceFlag,
						help.IpAddressFlag,
						help.AddFlag,
					),
				)
				os.Exit(help.ExitSetupFailed)
			}
		case help.ForwIpv4Flag, help.ForwIpv6Flag:
			indx++
			if indx < len(os.Args) {
				if help.AddFlag == os.Args[indx] {
					param.ForwardIpvArray[0] = os.Args[indx-1]
					param.ForwardIpvArray[1] = help.AddFlag
				} else if help.DelFlag == os.Args[indx] {
					param.ForwardIpvArray[0] = os.Args[indx-1]
					param.ForwardIpvArray[1] = help.DelFlag
				} else {
					indx--
				}
			} else {
				indx--
				help.ErrorExitMessage(
					os.Args[indx],
					fmt.Sprintf("Invalid argument passed. "+
						"Example (e.g. [%s %s or %s %s] etc.)",
						help.ForwIpv4Flag,
						help.AddFlag,
						help.ForwIpv6Flag,
						help.DelFlag,
					),
				)
				os.Exit(help.ExitSetupFailed)
			}
		default:
			help.ErrorExitMessage(
				os.Args[indx],
				DefaultErrorMessage,
			)
			os.Exit(help.ExitSetupFailed)
		}

	}
	param.WgSet(true)

}

// Method for processing flags to remove, enable, or disable a network interface.
func (param *ReceivedArgsStructure) InterfaceArgsHandler(indx int) int {
	if param.InterfaceNameArray[0] != "" {
		help.ErrorExitMessage(
			help.WgInterfaceFlag,
			DefaultErrorMessage,
		)
		os.Exit(help.ExitSetupFailed)
	}

	indx++
	if indx < len(os.Args) {

		if strings.ContainsAny(os.Args[indx-1], help.RegexSymbols) {
			msg := fmt.Sprintf(
				"Invalid character in interface name [%s]. Example: wg0, wg1",
				os.Args[indx-1],
			)
			help.ErrorExitMessage(help.WgInterfaceFlag, msg)
			os.Exit(help.ExitSetupFailed)
		}
		currentInterface := os.Args[indx-1]

		if help.DelFlag == os.Args[indx] {
			param.InterfaceNameArray[0] = help.DelFlag
			param.InterfaceNameArray[1] = currentInterface
		} else if help.EnableWgInterfaceFlag == os.Args[indx] {
			param.InterfaceNameArray[0] = help.EnableWgInterfaceFlag
			param.InterfaceNameArray[1] = currentInterface
		} else if help.DisableWgInterfaceFlag == os.Args[indx] {
			param.InterfaceNameArray[0] = help.DisableWgInterfaceFlag
			param.InterfaceNameArray[1] = currentInterface
		} else if help.UpdateFlag == os.Args[indx] {
			indx++
			if indx < len(os.Args) {
				if help.PortFlag == os.Args[indx] {
					indx++
					if indx < len(os.Args) {
						param.InterfaceNameArray[0] = help.UpdateFlag + help.PortFlag
						param.InterfaceNameArray[1] = fmt.Sprintf(
							"%s, %s", currentInterface, os.Args[indx])
					} else {
						indx -= 3
					}

				} else if help.PrivateKeyFlag == os.Args[indx] {
					indx++
					if indx < len(os.Args) {
						if len(os.Args[indx]) < 44 {
							help.ErrorExitMessage(
								help.PeerFlag,
								"Invalid public key length (base64)",
							)
							os.Exit(help.ExitSetupFailed)
						}

						param.InterfaceNameArray[1] = fmt.Sprintf(
							"%s, %s", currentInterface, os.Args[indx])
					} else {
						param.InterfaceNameArray[1] = currentInterface
					}
					param.InterfaceNameArray[0] = help.UpdateFlag + help.PrivateKeyFlag
				} else {
					indx--
				}
			} else {
				indx -= 2
			}

		} else if help.PeerFlag == os.Args[indx] {
			indx++
			if indx < len(os.Args) {
				if len(os.Args[indx]) < 44 {
					help.ErrorExitMessage(
						help.PeerFlag,
						"Invalid public key length (base64)",
					)
					os.Exit(help.ExitSetupFailed)
				}

				param.InterfaceNameArray[1] = fmt.Sprintf(
					"%s, %s, %s, ",
					help.WgInterfaceFlag,
					currentInterface,
					os.Args[indx],
				)

				indx++
				if indx < len(os.Args) && os.Args[indx] == help.DelFlag {
					param.InterfaceNameArray[0] = help.PeerFlag + help.DelFlag
				} else {
					param.InterfaceNameArray[0] = help.PeerFlag + help.AddFlag
					param.InterfaceNameArray[1] += strings.Join(os.Args[indx:], ", ")
					indx += len(os.Args)
				}

			} else {
				indx -= 2
			}

		} else {
			indx--
			param.InterfaceNameArray[0] = help.WgInterfaceFlag
			param.InterfaceNameArray[1] = currentInterface
		}

	} else {
		help.ErrorExitMessage(
			help.WgInterfaceFlag,
			DefaultErrorMessage,
		)
		os.Exit(help.ExitSetupFailed)
	}

	return indx
}

// Method for processing flags to add or remove an IP address.
func (param *ReceivedArgsStructure) IpAddressArgsHandler(indx int) int {

	if param.IpAddressArray[0] != "" {
		help.ErrorExitMessage(
			help.IpAddressFlag,
			DefaultErrorMessage,
		)
		os.Exit(help.ExitSetupFailed)
	}

	indx++
	if indx < len(os.Args) {

		ip, ipnet := help.IpAddressValid(
			fmt.Sprintf(
				"%s %s %s %s %s",
				help.WgInterfaceFlag,
				param.InterfaceNameArray[1],
				help.IpAddressFlag,
				os.Args[indx-1],
				os.Args[indx],
			),
			os.Args[indx-1],
		)

		mask, _ := ipnet.Mask.Size()

		// Check IP.
		if help.AddFlag == os.Args[indx] {
			param.IpAddressArray[0] = help.AddFlag
			param.IpAddressArray[1] = fmt.Sprintf("%s/%v", ip.String(), mask)
		} else if help.DelFlag == os.Args[indx] {
			param.IpAddressArray[0] = help.DelFlag
			param.IpAddressArray[1] = fmt.Sprintf("%s/%v", ip.String(), mask)
		} else {
			help.ErrorExitMessage(
				os.Args[indx],
				DefaultErrorMessage,
			)
			os.Exit(help.ExitSetupFailed)
		}

		// Check NAT.
		indx++
		if indx < len(os.Args) {
			if help.NatFlag == os.Args[indx] || help.FirewallFlag == os.Args[indx] {

				currentFlag := os.Args[indx]

				indx++
				if indx < len(os.Args) {

					param.NatArray[0] = currentFlag
					param.NatArray[1] = ipnet.String()

					iface, _ := get.GetExistInterface(
						os.Args[indx],
					)
					if !iface {
						help.ErrorExitMessage(
							help.NatFlag,
							fmt.Sprintf("Network interface [%s] "+
								"not found or entered incorrectly",
								os.Args[indx]),
						)
						os.Exit(help.ExitSetupFailed)
					}

					param.NatArray[2] = os.Args[indx]

				} else {
					param.NatArray[0] = currentFlag
					param.NatArray[1] = ipnet.String()
					param.NatArray[2] = shell.GetNetInterfaceNameLinux()
				}
			} else {
				help.ErrorExitMessage(
					os.Args[indx],
					DefaultErrorMessage,
				)
				os.Exit(help.ExitSetupFailed)
			}
		}

	} else {
		help.ErrorExitMessage(
			help.IpAddressFlag,
			DefaultErrorMessage,
		)
		os.Exit(help.ExitSetupFailed)
	}

	return indx
}

// Method for running commands in Linux shell.
func (param *ReceivedArgsStructure) WgSet(stdCmd bool) {

	var cmd string

	// Flag: [-i].
	switch param.InterfaceNameArray[0] {
	// Delete network interface.
	case help.DelFlag:
		cmd = shell.FormatCmdIpLinkDelete(param.InterfaceNameArray[1])
		err := shell.ShellCommand(cmd, stdCmd)
		if err != nil {
			help.ErrorExitMessage("", fmt.Sprintf("%v", err))
			os.Exit(help.ExitSetupFailed)
		}
	// Network interface up.
	case help.EnableWgInterfaceFlag:
		cmd = shell.FormatCmdIpLinkSet(
			param.InterfaceNameArray[1],
			shell.IpUp,
		)
		err := shell.ShellCommand(cmd, stdCmd)
		if err != nil {
			help.ErrorExitMessage("", fmt.Sprintf("%v", err))
			os.Exit(help.ExitSetupFailed)
		}
	// Network interface down.
	case help.DisableWgInterfaceFlag:
		cmd = shell.FormatCmdIpLinkSet(
			param.InterfaceNameArray[1],
			shell.IpDown,
		)
		err := shell.ShellCommand(cmd, stdCmd)
		if err != nil {
			help.ErrorExitMessage("", fmt.Sprintf("%v", err))
			os.Exit(help.ExitSetupFailed)
		}
	// Updating PrivateKey in Wireguard network.
	case help.UpdateFlag + help.PrivateKeyFlag:

		args := strings.Split(param.InterfaceNameArray[1], ", ")
		param := set.UpdatePrivateKeyStructure{}

		if len(args) == 2 {
			param.InterfaceName = args[0]
			param.PrivateKey = args[1]
		} else {
			param.InterfaceName = args[0]
		}

		err := set.UpdatePrivateKey(param)
		if err != nil {
			help.ErrorExitMessage(
				help.PrivateKeyFlag,
				fmt.Sprintf("%v", err),
			)
			os.Exit(help.ExitSetupFailed)
		}
	// Updating the port in the added Wireguard network.
	case help.UpdateFlag + help.PortFlag:
		args := strings.Split(param.InterfaceNameArray[1], ", ")
		err := set.UpdatePort(args[0], args[1])
		if err != nil {
			help.ErrorExitMessage(
				help.PortFlag,
				fmt.Sprintf("%v", err),
			)
			os.Exit(help.ExitSetupFailed)
		}
	// Delete peer from Wireguard network.
	case help.PeerFlag + help.DelFlag:
		flags := strings.Split(param.InterfaceNameArray[1], ", ")
		cfg := set.SinglePeerStructure{
			InterfaceName: flags[1],
			PublicKey:     flags[2],
		}
		err := cfg.RemovePeer()
		if err != nil {
			help.ErrorExitMessage(
				help.DelFlag,
				fmt.Sprintf("%v", err),
			)
			os.Exit(help.ExitSetupFailed)
		}
	// Adding peer to a Wireguard network.
	case help.PeerFlag + help.AddFlag:
		flags := strings.Split(param.InterfaceNameArray[1], ", ")
		var cfg set.SinglePeerStructure

		cfg.InterfaceName = flags[1]
		cfg.PublicKey = flags[2]

		lenght := len(flags[3:])
		args := flags[3:]

		for indx := 0; indx < lenght; indx++ {
			if args[indx] == help.AddFlag {
				indx++
				if indx < lenght {
					cfg.AllowedIPs = []string{args[indx]}
				} else {
					help.ErrorExitMessage(
						args[indx-1],
						DefaultErrorMessage,
					)
					os.Exit(help.ExitSetupFailed)
				}

			} else if args[indx] == help.KeepaliveFlag {
				indx++
				if indx < lenght {
					cfg.PersistentKeepaliveInterval = args[indx]
				} else {
					help.ErrorExitMessage(
						args[indx-1],
						DefaultErrorMessage,
					)
					os.Exit(help.ExitSetupFailed)
				}
			} else if args[indx] == help.EndPointHostFlag {
				indx++
				if indx < lenght {
					cfg.EndpointHost = args[indx]
				} else {
					help.ErrorExitMessage(
						args[indx-1],
						DefaultErrorMessage,
					)
					os.Exit(help.ExitSetupFailed)
				}
			} else {
				help.ErrorExitMessage(
					args[indx],
					DefaultErrorMessage,
				)
				os.Exit(help.ExitSetupFailed)
			}

		}
		err := cfg.AddPeer(false)
		if err != nil {
			help.ErrorExitMessage(
				help.PeerFlag,
				fmt.Sprintf("%v", err),
			)
			os.Exit(help.ExitSetupFailed)
		}
	}

	// Flag: [-ip].
	switch param.IpAddressArray[0] {
	case help.AddFlag:
		// Add rules.
		if param.NatArray[0] == help.NatFlag {

			// Firewall.
			getFw, err := get.GetIptablesFirewall()
			if err != nil {
				help.ErrorExitMessage("", fmt.Sprintf("%v", err))
				os.Exit(help.ExitSetupFailed)
			}
			filter := get.FilterIptablesOutput{Rule: getFw}
			isGetFw, err := filter.GetExistingRules(
				param.InterfaceNameArray[1], param.NatArray[2], param.NatArray[1],
			)
			if err != nil {
				help.ErrorExitMessage("", fmt.Sprintf("%v", err))
				os.Exit(help.ExitSetupFailed)
			}
			if !isGetFw {
				cmd = shell.FormatCmdIptablesFirewall(
					shell.IpTablesAdd,
					param.NatArray[2],
					param.InterfaceNameArray[1],
				)
				err := shell.ShellCommand(cmd, stdCmd)
				if err != nil {
					help.ErrorExitMessage("", fmt.Sprintf("%v", err))
					os.Exit(help.ExitSetupFailed)
				}
			}

			// NAT.
			getNat, err := get.GetIptablesNAT()
			if err != nil {
				help.ErrorExitMessage("", fmt.Sprintf("%v", err))
				os.Exit(help.ExitSetupFailed)
			}
			filter = get.FilterIptablesOutput{Rule: getNat}
			isGetNat, err := filter.GetExistingRules(
				param.InterfaceNameArray[1], param.NatArray[2], param.NatArray[1],
			)
			if err != nil {
				help.ErrorExitMessage("", fmt.Sprintf("%v", err))
				os.Exit(help.ExitSetupFailed)
			}
			if !isGetNat {
				cmd = shell.FormatCmdIptablesNat(
					shell.IpTablesAdd,
					param.NatArray[2],
					param.NatArray[1],
				)
				err := shell.ShellCommand(cmd, stdCmd)
				if err != nil {
					help.ErrorExitMessage("", fmt.Sprintf("%v", err))
					os.Exit(help.ExitSetupFailed)
				}
			}
		} else {
			// Add IP address.
			cmd = shell.FormatCmdIpAddrDev(
				param.InterfaceNameArray[1],
				param.IpAddressArray[1],
				shell.IpAdd,
			)

			err := shell.ShellCommand(cmd, stdCmd)
			if err != nil {
				help.ErrorExitMessage("", fmt.Sprintf("%v", err))
				os.Exit(help.ExitSetupFailed)
			}
		}
	case help.DelFlag:
		// Delete rules.
		if param.NatArray[0] == help.FirewallFlag {
			getFw, err := get.GetIptablesFirewall()
			if err != nil {
				help.ErrorExitMessage("", fmt.Sprintf("%v", err))
				os.Exit(help.ExitSetupFailed)
			}
			filter := get.FilterIptablesOutput{Rule: getFw}
			isGetFw, err := filter.GetExistingRules(
				param.InterfaceNameArray[1], param.NatArray[2], param.NatArray[1],
			)
			if err != nil {
				help.ErrorExitMessage("", fmt.Sprintf("%v", err))
				os.Exit(help.ExitSetupFailed)
			}
			if isGetFw {
				cmd = shell.FormatCmdIptablesFirewall(
					shell.IpTablesDel,
					param.NatArray[2],
					param.InterfaceNameArray[1],
				)
				err := shell.ShellCommand(cmd, stdCmd)
				if err != nil {
					help.ErrorExitMessage("", fmt.Sprintf("%v", err))
					os.Exit(help.ExitSetupFailed)
				}
			}
		} else if param.NatArray[0] == help.NatFlag {
			getNat, err := get.GetIptablesNAT()
			if err != nil {
				help.ErrorExitMessage("", fmt.Sprintf("%v", err))
				os.Exit(help.ExitSetupFailed)
			}
			filter := get.FilterIptablesOutput{Rule: getNat}
			isGetNat, err := filter.GetExistingRules(
				param.InterfaceNameArray[1], param.NatArray[2], param.NatArray[1],
			)
			if err != nil {
				help.ErrorExitMessage("", fmt.Sprintf("%v", err))
				os.Exit(help.ExitSetupFailed)
			}
			if isGetNat {
				cmd = shell.FormatCmdIptablesNat(
					shell.IpTablesDel,
					param.NatArray[2],
					param.NatArray[1],
				)
				err := shell.ShellCommand(cmd, stdCmd)
				if err != nil {
					help.ErrorExitMessage("", fmt.Sprintf("%v", err))
					os.Exit(help.ExitSetupFailed)
				}
			}
		} else {
			// Delete IP address.
			cmd = shell.FormatCmdIpAddrDev(
				param.InterfaceNameArray[1],
				param.IpAddressArray[1],
				shell.IpDel,
			)
			err := shell.ShellCommand(cmd, stdCmd)
			if err != nil {
				help.ErrorExitMessage("", fmt.Sprintf("%v", err))
				os.Exit(help.ExitSetupFailed)
			}
		}

	}

	// Flag: [-fw4] or [-fw6].
	switch param.ForwardIpvArray[0] {
	case help.ForwIpv4Flag, help.ForwIpv6Flag:
		cmdMap := map[string]string{
			// IPv4
			"fw4a": shell.SysctlIpv4Up,
			"fw4d": shell.SysctlIpv4Down,
			// IPv6
			"fw6a": shell.SysctlIpv6Up,
			"fw6d": shell.SysctlIpv6Down,
		}
		flag := strings.Join(param.ForwardIpvArray[:2], "")

		cmd = cmdMap[strings.Replace(flag, "-", "", 2)]
		err := shell.ShellCommand(cmd, stdCmd)
		if err != nil {
			help.ErrorExitMessage("", fmt.Sprintf("%v", err))
			os.Exit(help.ExitSetupFailed)
		}

		cmd = shell.SysctlRules
		err = shell.ShellCommand(cmd, stdCmd)
		if err != nil {
			help.ErrorExitMessage("", fmt.Sprintf("%v", err))
			os.Exit(help.ExitSetupFailed)
		}
	}
}
