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
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/AlexKira/brgnetuse/internal/handlers"
	"github.com/AlexKira/brgnetuse/internal/help"
	"github.com/AlexKira/brgnetuse/internal/shell"
	"github.com/AlexKira/brgnetuse/src/get"
	"github.com/AlexKira/brgnetuse/src/set"
)

// Main entry point.
func main() {
	if len(os.Args) < 2 || os.Args[1] == help.HelpFlag {
		help.BridgeSetWgHelp()
		return
	}

	lenghtArgs := len(os.Args) - 1
	flag := os.Args[1]

	var data []string

	if lenghtArgs >= 3 {
		flag = os.Args[1] + os.Args[3]
		data = os.Args[2:]
	} else if lenghtArgs == 2 {
		flag = os.Args[1] + os.Args[2]
		data = os.Args[1:]
	}

	obj, ok := СommandMap[flag]
	if !ok {
		help.ErrorExitMessage(
			os.Args[lenghtArgs],
			help.DefaultErrorMessage,
		)
		os.Exit(help.ExitSetupFailed)
	}

	cmd := obj()

	curArgs, err := cmd.ParseArgs(data)
	if err != nil {
		help.ErrorExitMessage(
			curArgs,
			err.Error(),
		)
		os.Exit(help.ExitSetupFailed)
	}

	if err := cmd.Execute(); err != nil {
		help.ErrorExitMessage(
			curArgs,
			err.Error(),
		)
		os.Exit(help.ExitSetupFailed)
	}
}

// Enables standard output for shell commands.
const ShellStd bool = true

// Main command management interface.
type Command interface {
	ParseArgs(args []string) (string, error)
	Execute() error
}

type CommandRegistry map[string]func() Command

var СommandMap = CommandRegistry{
	// Flag: [-i].
	help.WgInterfaceFlag + help.DelFlag:                func() Command { return &InterfaceCommand{} },
	help.WgInterfaceFlag + help.DisableWgInterfaceFlag: func() Command { return &InterfaceCommand{} },
	help.WgInterfaceFlag + help.EnableWgInterfaceFlag:  func() Command { return &InterfaceCommand{} },

	// Flag: [-i -u].
	help.WgInterfaceFlag + help.UpdateFlag: func() Command { return &UpdateInterfaceCommand{} },

	// Flag: [-i -pr].
	help.WgInterfaceFlag + help.PeerFlag: func() Command { return &PeerCommand{} },

	// Flag: [-i -ip].
	help.WgInterfaceFlag + help.IpAddressFlag: func() Command { return &IpIntertfaceCommand{} },

	// Flag: [-fw4 -a|-d ].
	help.ForwIpv4Flag + help.AddFlag: func() Command { return &IpForwardingCommand{} },
	help.ForwIpv4Flag + help.DelFlag: func() Command { return &IpForwardingCommand{} },

	// Flag: [-fw6 -a|-d ].
	help.ForwIpv6Flag + help.AddFlag: func() Command { return &IpForwardingCommand{} },
	help.ForwIpv6Flag + help.DelFlag: func() Command { return &IpForwardingCommand{} },

	// Flag: [-fpu -a|-d].
	help.FirewallFlag + help.AddFlag: func() Command { return &FirewallPortCommand{} },
	help.FirewallFlag + help.DelFlag: func() Command { return &FirewallPortCommand{} },
}

// InterfaceCommand encapsulates the 'interface' command's data and logic.
// It holds the interface's name and the action to perform on it.
type InterfaceCommand struct {
	Cmd string
}

// Method parses the command-line arguments for the interface command,
// validating the interface name and setting the internal command string.
func (p *InterfaceCommand) ParseArgs(args []string) (string, error) {

	if strings.ContainsAny(args[0], help.RegexSymbols) {
		errMsg := fmt.Sprintf(
			"error: invalid character in interface name [%s], example: 'wg0, wg1'",
			args[0],
		)
		return args[1], errors.New(errMsg)
	}

	switch args[1] {
	case help.DelFlag:
		p.Cmd = shell.FormatCmdIpLinkDelete(args[0])
	case help.EnableWgInterfaceFlag:
		p.Cmd = shell.FormatCmdIpLinkSet(args[0], shell.IpUp)
	case help.DisableWgInterfaceFlag:
		p.Cmd = shell.FormatCmdIpLinkSet(args[0], shell.IpDown)
	}

	return help.WgInterfaceFlag, nil
}

// Method runs the shell command stored in Cmd to perform the interface operation.
func (p *InterfaceCommand) Execute() error {
	err := shell.ShellCommand(p.Cmd, ShellStd)
	if err != nil {
		return err
	}
	return nil
}

// UpdateInterface holds parameters for updating a network or system interface.
type UpdateInterfaceCommand struct {
	Iface   string
	Value   string
	FlagCmd string
}

// Method to parse arguments for updating the interface.
func (p *UpdateInterfaceCommand) ParseArgs(args []string) (string, error) {

	if len(args) < 3 {
		return help.UpdateFlag, errors.New(help.DefaultErrorMessage)
	}

	p.Iface = args[0]

	for indx := 2; indx < len(args); indx++ {
		switch args[indx] {
		case help.PrivateKeyFlag:
			indx++
			if indx < len(args) {
				p.Value = args[indx]
			}
			p.FlagCmd = help.PrivateKeyFlag

		case help.PortFlag:
			indx++
			if indx < len(args) {
				p.FlagCmd = help.PortFlag
				p.Value = args[indx]
			} else {
				return help.PortFlag, errors.New(help.DefaultErrorMessage)
			}
		default:
			return help.UpdateFlag, errors.New(help.DefaultErrorMessage)
		}
	}

	return help.UpdateFlag, nil
}

// Method to execute a command for updating the interface.
func (p *UpdateInterfaceCommand) Execute() error {

	typeAwg, err := help.CheckProcessTagExists(p.Iface, help.Env_Awg_Type)
	if err != nil {
		return err
	}

	switch p.FlagCmd {
	case help.PortFlag:

		if typeAwg {
			cmd := shell.FormatCmdAwgUpdatePort(p.Iface, p.Value)
			if err := shell.ShellCommand(cmd, ShellStd); err != nil {
				return err
			}

		} else {
			err := set.UpdatePort(p.Iface, p.Value)
			if err != nil {
				return err
			}
		}

	case help.PrivateKeyFlag:

		errMsg := "error: invalid public key length (base64)"
		if len(p.Value) > 0 && len(p.Value) < 44 {
			return errors.New(errMsg)
		}

		if typeAwg {

			if p.Value == "" {
				pk, err := get.GenerateKeys()
				if err != nil {
					return err
				}
				p.Value = pk["private"].String()
			}

			cmd := shell.FormatCmdAwgUpdatePrivateKey(p.Iface, p.Value)
			if err := shell.ShellCommand(cmd, ShellStd); err != nil {
				return err
			}

		} else {
			privKey := set.UpdatePrivateKeyStructure{
				InterfaceName: p.Iface,
				PrivateKey:    p.Value,
			}

			err := set.UpdatePrivateKey(privKey)
			if err != nil {
				return err
			}
		}

	}

	return nil
}

// PeerCommand encapsulates the data and logic for managing WireGuard peers.
// It holds all necessary parameters for adding or deleting a peer, such as
// interface name, public key, allowed IPs, keep-alive settings, and endpoint.
type PeerCommand struct {
	Iface        string
	Publickey    string
	AllowIps     []string
	KeepAlive    string
	EndPointHost string
	FlagCmd      string
}

// Method parses the command-line arguments for the peer management command.
// It extracts the interface name, public key, allowed IPs, and optional
// keep-alive and endpoint host settings based on the provided arguments.
// It returns the main command flag (help.PeerFlag) and an error if parsing fails.
func (p *PeerCommand) ParseArgs(args []string) (string, error) {

	if len(args) <= 3 {
		errMsg := "error: invalid command arguments, please provide private " +
			"key and subnet address"
		return help.PeerFlag, errors.New(errMsg)
	}

	currentAlwips := 0
	endAlwIps := len(args)

	p.Iface = args[0]
	p.Publickey = args[2]
	for indx := 3; indx < len(args); indx++ {
		switch args[indx] {
		case help.AddFlag:
			p.FlagCmd = help.AddFlag

			indx++
			if indx < len(args) {
				currentAlwips = len(args[(endAlwIps - indx):endAlwIps])
			} else {
				return help.AddFlag, errors.New(help.DefaultErrorMessage)
			}

		case help.KeepaliveFlag:
			endAlwIps = indx

			indx++
			if indx < len(args) {
				p.KeepAlive = args[indx]
			} else {
				return help.KeepaliveFlag, errors.New(help.DefaultErrorMessage)
			}

			indx++
			if indx < len(args) {
				if args[indx] == help.EndPointHostFlag {

					indx++
					if indx < len(args) {
						p.EndPointHost = args[indx]
					} else {
						return help.EndPointHostFlag, errors.New(help.DefaultErrorMessage)
					}
				} else {
					return args[indx], errors.New(help.DefaultErrorMessage)
				}

			}

		case help.DelFlag:
			p.FlagCmd = help.DelFlag
		}
	}

	p.AllowIps = args[currentAlwips:endAlwIps]

	return help.PeerFlag, nil
}

// Method performs the peer management operation (add or delete) based on the parsed arguments.
// It constructs a SinglePeerStructure and calls the appropriate method (AddPeer or RemovePeer)
// to apply the changes to the WireGuard configuration.
func (p *PeerCommand) Execute() error {

	typeAwg, err := help.CheckProcessTagExists(p.Iface, help.Env_Awg_Type)
	if err != nil {
		return err
	}

	var obj set.SinglePeerStructure
	switch p.FlagCmd {
	case help.AddFlag:

		if typeAwg {
			cmd := shell.FormatCmdAwgAddPeer(
				p.Iface, p.Publickey,
				strings.Join(p.AllowIps, ", "),
				p.KeepAlive, p.EndPointHost)
			if err := shell.ShellCommand(cmd, ShellStd); err != nil {
				return err
			}

		} else {
			obj.InterfaceName = p.Iface
			obj.PublicKey = p.Publickey
			obj.AllowedIPs = strings.Split(strings.Join(p.AllowIps, ","), ",")
			obj.PersistentKeepaliveInterval = p.KeepAlive
			obj.EndpointHost = p.EndPointHost
			err := obj.AddPeer(false)
			if err != nil {
				return err
			}
		}

	case help.DelFlag:

		if typeAwg {
			cmd := shell.FormatCmdAwgDeletePeer(p.Iface, p.Publickey)
			if err := shell.ShellCommand(cmd, ShellStd); err != nil {
				return err
			}

		} else {
			obj.InterfaceName = p.Iface
			obj.PublicKey = p.Publickey

			if err := obj.RemovePeer(); err != nil {
				return err
			}
		}

	}
	return nil
}

// IpIntertfaceCommand encapsulates the data and logic for managing IP addresses
// and associated firewall/NAT rules on network interfaces.
type IpIntertfaceCommand struct {
	InIface  string
	SubNet   string
	OutIface string
	FlagCmd  string
}

// Method parses the command-line arguments for the IP interface command.
// It extracts the input interface, subnet, action flag, and optional
// output interface for NAT/firewall operations.
// It returns the main command flag (help.IpAddressFlag) and an error if parsing fails.
func (p *IpIntertfaceCommand) ParseArgs(args []string) (string, error) {
	if len(args) < 4 {
		errMsg := fmt.Sprintf(
			"error: invalid command arguments, specify action: [%s | %s]",
			help.AddFlag,
			help.DelFlag,
		)
		return help.IpAddressFlag, errors.New(errMsg)
	}

	p.InIface = args[0]
	for indx := 3; indx < len(args); indx++ {

		switch args[indx] {
		case help.AddFlag, help.DelFlag:
			p.SubNet = args[indx-1]
			p.FlagCmd = args[indx]

			// Check args: Firewall, NAT
			indx++
			if indx < len(args) {

				switch args[indx] {
				case help.NatFlag, help.FirewallFlag:
					p.FlagCmd = p.FlagCmd + args[indx]

					indx++
					if indx < len(args) {
						p.OutIface = args[indx]
					}

				default:
					errMsg := fmt.Sprintf(
						"error: invalid command arguments, specify action: [%s | %s]",
						help.NatFlag,
						help.FirewallFlag,
					)
					return help.IpAddressFlag, errors.New(errMsg)
				}
			}

		default:
			return help.IpAddressFlag, errors.New(help.DefaultErrorMessage)
		}
	}
	return help.IpAddressFlag, nil
}

// Method execute performs the IP address and/or firewall/NAT operations based on the parsed arguments.
// It constructs and executes shell commands using 'ip' or 'iptables'.
func (p *IpIntertfaceCommand) Execute() error {

	_, ipnet := help.IpAddressValid(
		fmt.Sprintf(
			"%s %s %s %s %s",
			help.WgInterfaceFlag,
			p.InIface,
			help.IpAddressFlag,
			p.SubNet,
			strings.TrimSpace(
				strings.Join(
					strings.Split(
						p.FlagCmd, "-"), " -",
				),
			),
		),
		p.SubNet,
	)

	ipAction := shell.IpAdd
	if p.FlagCmd == help.DelFlag {
		ipAction = shell.IpDel
	}

	if p.OutIface == "" {
		p.OutIface = shell.GetNetInterfaceNameLinux()
	}

	switch p.FlagCmd {
	case help.AddFlag, help.DelFlag:

		cmd := shell.FormatCmdIpAddrDev(
			p.InIface,
			p.SubNet,
			ipAction,
		)

		err := shell.ShellCommand(cmd, ShellStd)
		if err != nil {
			return err
		}

	case help.AddFlag + help.NatFlag, help.AddFlag + help.FirewallFlag:

		isExistFirewall, isExistNat, err := getRules(
			p.InIface, p.OutIface, ipnet.String(), "all",
		)
		if err != nil {
			return err
		}

		if !isExistFirewall {
			cmd := shell.FormatCmdIptablesFirewall(shell.IpTablesAdd, p.OutIface, p.InIface)
			if err = shell.ShellCommand(cmd, ShellStd); err != nil {
				return err
			}
		}

		if !isExistNat {
			cmd := shell.FormatCmdIptablesNat(shell.IpTablesAdd, p.OutIface, ipnet.String())
			if err := shell.ShellCommand(cmd, ShellStd); err != nil {
				return err
			}
		}

	case help.DelFlag + help.NatFlag:

		_, isExistNat, err := getRules(p.InIface, p.OutIface, ipnet.String(), "nat")
		if err != nil {
			return err
		}
		if isExistNat {
			cmd := shell.FormatCmdIptablesNat(shell.IpTablesDel, p.OutIface, ipnet.String())
			if err := shell.ShellCommand(cmd, ShellStd); err != nil {
				return err
			}
		}

	case help.DelFlag + help.FirewallFlag:
		isExistFirewall, _, err := getRules(p.InIface, p.OutIface, ipnet.String(), "fr")
		if err != nil {
			return err
		}

		if isExistFirewall {
			cmd := shell.FormatCmdIptablesFirewall(shell.IpTablesDel, p.OutIface, p.InIface)
			if err = shell.ShellCommand(cmd, ShellStd); err != nil {
				return err
			}
		}

	}

	return nil
}

// Function checks for the existence of specified iptables firewall and/or NAT rules.
// It queries the system for existing rules and filters them based on interface names and IP network.
//
// Parameters:
//
//	inIface: The input network interface name.
//	outIface: The output network interface name.
//	ipNet: The IP network string (e.g., "10.0.0.0/24").
//	rule: Specifies which type of rule to check: "fr" for firewall, "nat" for NAT, or "all" for both.
//
// Returns:
//
//	isGetFw: True if a matching firewall rule is found.
//	isGetNat: True if a matching NAT rule is found.
//	error: An error if an invalid interface is detected or rule retrieval fails.
func getRules(inIface, outIface, ipNet, rule string) (bool, bool, error) {

	var isGetFw, isGetNat bool

	isExistIface, err := get.GetExistInterface(outIface)
	if err != nil {
		return false, false, err
	}

	if !isExistIface {
		errMsg := fmt.Sprintf(
			"error: network interface: '%s' not found or entered incorrectly",
			outIface,
		)
		return false, false, errors.New(errMsg)
	}

	if rule == "fr" || rule == "all" {
		getFw, err := get.GetIptablesFirewall()
		if err != nil {
			return false, false, err
		}

		filter := get.FilterIptablesOutput{Rule: getFw}
		isGetFw, err = filter.GetExistingRules(inIface, outIface, ipNet)
		if err != nil {
			return false, false, err
		}

	}

	if rule == "nat" || rule == "all" {
		getNat, err := get.GetIptablesNAT()
		if err != nil {
			return false, false, err
		}

		filter := get.FilterIptablesOutput{Rule: getNat}
		isGetNat, err = filter.GetExistingRules(inIface, outIface, ipNet)
		if err != nil {
			return false, false, err
		}
	}

	return isGetFw, isGetNat, nil
}

// IpForwardingCommand encapsulates the data and logic for managing
// IP packet forwarding (IPv4 and IPv6) at the system kernel level.
type IpForwardingCommand struct {
	Cmd string
}

// Method parses the command-line arguments for the IP forwarding command.
// It determines which sysctl command to execute for enabling or disabling
// IPv4 or IPv6 forwarding based on the provided arguments.
//
// It returns a string flag indicating the type of IP forwarding operation (IPv4/IPv6),
// and an error if parsing fails.
func (p *IpForwardingCommand) ParseArgs(args []string) (string, error) {

	flag := fmt.Sprintf("%s | %s", help.ForwIpv4Flag, help.ForwIpv6Flag)
	if len(args) == 0 {
		return flag, errors.New(help.DefaultErrorMessage)
	}

	cmdMap := map[string]string{
		// IPv4
		help.ForwIpv4Flag + help.AddFlag: shell.SysctlIpv4Up,
		help.ForwIpv4Flag + help.DelFlag: shell.SysctlIpv4Down,

		// IPv6
		help.ForwIpv6Flag + help.AddFlag: shell.SysctlIpv6Up,
		help.ForwIpv6Flag + help.DelFlag: shell.SysctlIpv6Down,
	}

	cmd, ok := cmdMap[strings.Join(args, "")]
	if !ok {
		return flag, errors.New("internal error: unrecognized forwarding key argument")
	}

	p.Cmd = cmd

	return flag, nil
}

// Method execute runs the configured sysctl command to manage IP forwarding
// and then applies the sysctl rules.
func (p *IpForwardingCommand) Execute() error {

	if err := shell.ShellCommand(p.Cmd, ShellStd); err != nil {
		return err
	}

	if err := shell.ShellCommand(shell.SysctlRules, ShellStd); err != nil {
		return err
	}

	return nil
}

type FirewallPortCommand struct {
	Cmd string
}

func (p *FirewallPortCommand) ParseArgs(args []string) (string, error) {

	if len(args) < 3 || len(args) > 3 {
		errMsg := "error: invalid command arguments, please specify a port number"
		return help.FirewallFlag, errors.New(errMsg)
	}

	cmdMap := map[string]shell.IpFlagString{
		// Type: UDP
		help.UpdateFlag + help.AddFlag: shell.IpTablesAdd,
		help.UpdateFlag + help.DelFlag: shell.IpTablesDel,
	}

	port := args[2]
	cmd, ok := cmdMap[args[0]+args[1]]
	if !ok {
		return fmt.Sprintf(
			"%s %s %s",
			help.FirewallFlag,
			args[0],
			args[1],
		), errors.New("internal error: unrecognized firewall key argument")
	}

	_, err := handlers.CheckPort(port)
	if err != nil {
		return help.FirewallFlag, err
	}

	p.Cmd = shell.FormatCmdIptablesFirewallPort(cmd, port)

	return help.FirewallFlag, nil
}

func (p *FirewallPortCommand) Execute() error {
	if err := shell.ShellCommand(p.Cmd, ShellStd); err != nil {
		return err
	}
	return nil
}
