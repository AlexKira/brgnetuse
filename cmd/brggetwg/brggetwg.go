//go:build !windows

/*
The brggetwg utility is designed to retrieve information about the current state of the server's internal network configuration.

Capabilities:
- Retrieve the current IP configuration of network interfaces (IP addresses, subnet masks, etc.).
- Retrieve detailed information about WireGuard interface and peer configurations.
- Retrieve information about NAT and Firewall rules.
- Retrieve the status of IPv4 and IPv6 forwarding.
- Generate Base64-encoded private and public keys for WireGuard peer configuration.
*/
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/AlexKira/brgnetuse/internal/help"
	"github.com/AlexKira/brgnetuse/internal/shell"
	"github.com/AlexKira/brgnetuse/src/get"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	Reset  = "\x1b[0m"
	Green  = "\x1b[32m"
	Bold   = "\x1b[1m"
	Yellow = "\x1b[33m"
	Cyan   = "\x1b[36m"
)

// Main entry point.
func main() {
	if len(os.Args) < 2 || os.Args[1] == help.HelpFlag {
		help.BridgeGetWgHelp()
		return
	}

	lenghtArgs := len(os.Args) - 1

	switch lenghtArgs {
	case 3:
		currentFlag, err := GetInterfaceCommnd(os.Args[1:])
		if err != nil {
			help.ErrorExitMessage(currentFlag, err.Error())
			os.Exit(help.ExitSetupFailed)
		}
	case 1:
		currentFlag, err := SingleCommand(os.Args[1])
		if err != nil {
			help.ErrorExitMessage(currentFlag, err.Error())
			os.Exit(help.ExitSetupFailed)
		}

	default:
		help.ErrorExitMessage(
			os.Args[lenghtArgs],
			help.DefaultErrorMessage,
		)
		os.Exit(help.ExitSetupFailed)
	}

}

// Enables standard output for shell commands.
const ShellStd bool = true

// Function processes commands requiring an interface name and a sub-flag.
// Expected format: `[main_flag] [interface_name] [sub_flag]`.
// It validates arguments, confirms interface existence, and then performs actions
// like displaying peers or IP addresses based on the sub-flag.
// Returns the main flag string for error context or an error if validation/execution fails.
func GetInterfaceCommnd(args []string) (string, error) {

	var iFaceName string

	if len(args) < 3 || len(args) > 3 {
		return help.WgInterfaceFlag, errors.New(help.DefaultErrorMessage)
	}

	iFaceName = args[1]

	iface, err := get.GetExistInterface(iFaceName)
	if err != nil {
		return help.WgInterfaceFlag, err
	}
	if !iface {
		return help.WgInterfaceFlag, fmt.Errorf(
			"error: network interface `%s` not found", iFaceName,
		)
	}

	switch args[2] {
	case help.PeerFlag:
		typeCmd, err := help.CheckProcessTagExists(iFaceName, help.Env_Awg_Type)
		if err != nil {
			return help.PeerFlag, err
		}

		if typeCmd {
			cmd := shell.FormatCmdAwgShow(iFaceName)
			if err := shell.ShellCommand(cmd, ShellStd); err != nil {
				return help.PeerFlag, err
			}

		} else {
			if err := printWgInterface(iFaceName); err != nil {
				return help.PeerFlag, err
			}
		}
	case help.IpAddressFlag:
		if err := printIP(iFaceName); err != nil {
			return help.IpAddressFlag, err
		}
	default:
		return help.WgInterfaceFlag, errors.New(help.DefaultErrorMessage)
	}

	return help.WgInterfaceFlag, nil
}

// Function handles single-flag operations that do not require additional
// arguments. It dispatches to specific helper functions based on the provided
// flag. Examples include displaying all IP addresses, generating keys, or showing
// firewall rules. Returns the processed flag string (for error context)
// or an error if an operation fails.
func SingleCommand(flag string) (string, error) {

	switch flag {
	case help.IpAddressFlag:
		if err := printIP(""); err != nil {
			return help.IpAddressFlag, err
		}
	case help.PeerFlag:

		if err := shell.ShellCommand(
			shell.FormatCmdAwgShow(""), ShellStd); err != nil {
			return help.PeerFlag, err
		}

		if err := printWgInterface(""); err != nil {
			return help.PeerFlag, err
		}

	case help.ForwardingFlag:
		resultMap, err := get.GetIPvForwarding()
		if err != nil {
			return help.ForwardingFlag, err
		}

		printFw(resultMap)

	case help.FirewallFlag:
		if err := printRules(false); err != nil {
			return help.FirewallFlag, err
		}

	case help.NatFlag:
		if err := printRules(true); err != nil {
			return help.NatFlag, err
		}
	case help.PrivateKeyFlag:
		resultMap, err := get.GenerateKeys()
		if err != nil {
			return help.PrivateKeyFlag, err
		}

		printWgKey(resultMap)

	default:
		return flag, errors.New(help.DefaultErrorMessage)

	}

	return flag, nil
}

// Function to show network interface data.
func printIP(name string) error {
	var result []get.IpInterfaceStructure
	if name == "" {
		resNet, err := get.GetIp()
		if err != nil {
			return err
		}
		result = resNet
	} else {
		resNet, err := get.GetIpShow(name)
		if err != nil {
			return err
		}
		result = resNet
	}

	interfaceFormat := `
name: %s
  index: %d
  flags: %s
  mtu: %d
  qdisc: %s
  operstate: %s
  group: %s
  txqlen: %d
  link_type: %s
  address: %s
  broadcast: %s

`
	addressFormat := `
addr_info: 
  family: %s
  local: %s,
  prefixlen: %d
  scope: %s
  dynamic: %t
  label: %s
  valid_life_time: %d
  preferred_life_time: %d

`

	for _, iface := range result {
		fmt.Printf(
			interfaceFormat,
			iface.IfName,
			iface.IfIndex,
			iface.Flags,
			iface.MTU,
			iface.Qdisc,
			iface.OperState,
			iface.Group,
			iface.TxQLen,
			iface.LinkType,
			iface.Address,
			iface.Broadcast,
		)
		for _, addrInfo := range iface.AddrInfo {
			fmt.Printf(
				addressFormat,
				addrInfo.Family,
				addrInfo.Local,
				addrInfo.Prefixlen,
				addrInfo.Scope,
				addrInfo.Dynamic,
				addrInfo.Label,
				addrInfo.ValidLifeTime,
				addrInfo.PreferredLifeTime,
			)
		}
	}
	return nil
}

// Function to display WireGuard network interface information.
func printWgInterface(name string) error {

	devices, err := get.GetPeer(name)

	if err != nil {
		return err
	}

	for _, d_val := range devices {
		printDevice(d_val)
		for _, p_val := range d_val.Peers {
			printPeer(p_val)
		}
	}

	return nil
}

// Function to parse WireGuard device information.
func printDevice(d *wgtypes.Device) {

	interfaceFormat := `
` + Green + Bold + `interface: ` + Reset + Green + `%s ` + Reset + `
` + Bold + `  public key: ` + Reset + `%s` + ` 
` + Bold + `  private key: ` + Reset + `(hidden)` + `
` + Bold + `  listening port: ` + Reset + `%d` + `
`
	fmt.Printf(
		interfaceFormat,
		d.Name,
		d.PublicKey.String(),
		d.ListenPort,
	)
}

// Function formats byte counts into human-readable strings (B, KiB, MiB, GiB)
// with units colored in Cyan.
func formatBytes(bytes int64) string {
	const (
		_   = iota
		KiB = 1 << (10 * iota) // 1 KiB = 1024 bytes
		MiB = 1 << (10 * iota) // 1 MiB = 1024 KiB
		GiB = 1 << (10 * iota)
	)

	fBytes := float64(bytes)
	switch {
	case fBytes >= GiB:
		return fmt.Sprintf("%.2f %sGiB%s", fBytes/GiB, Cyan, Reset)
	case fBytes >= MiB:
		return fmt.Sprintf("%.2f %sMiB%s", fBytes/MiB, Cyan, Reset)
	case fBytes >= KiB:
		return fmt.Sprintf("%.2f %sKiB%s", fBytes/KiB, Cyan, Reset)
	default:
		return fmt.Sprintf("%d %sB%s", bytes, Cyan, Reset)
	}
}

// Function to parse WireGuard peer information.
func printPeer(p wgtypes.Peer) {
	ipsString := func(ipns []net.IPNet) string {
		ss := make([]string, 0, len(ipns))
		for _, ipn := range ipns {
			ss = append(ss, ipn.String())
		}

		return strings.Join(ss, ", ")
	}

	fmt.Printf(`
`+Bold+Yellow+`peer: `+Reset+Yellow+`%s`+Reset+`
`+Bold+`  endpoint: `+Reset+`%s`+`
`+Bold+`  allowed ips: `+Reset+`%s`+`
`+Bold+`  transfer: `+Reset+`%s received, %s sent`+`
`+Bold+`  persistent keepalive: `+Reset+`every %d `+Cyan+`seconds`+Reset+`
`,
		p.PublicKey.String(),
		p.Endpoint.String(),
		strings.ReplaceAll(ipsString(p.AllowedIPs), "/", Cyan+"/"+Reset),
		formatBytes(p.ReceiveBytes),
		formatBytes(p.TransmitBytes),
		int(p.PersistentKeepaliveInterval.Seconds()),
	)
}

// Function to display IPv4 and IPv6 network forwarding information.
func printFw(p map[string]int) {
	fmt.Printf(`
net.ipv4.ip_forward: %d
net.ipv6.conf.all.forwarding: %d

`,
		p["ipv4"],
		p["ipv6"],
	)
}

// Function to display firewall and NAT table rules.
func printRules(nat bool) error {
	var result get.IptablesOutput
	if nat {
		resNat, err := get.GetIptablesNAT()
		if err != nil {
			return err
		}
		result = resNat
	} else {
		resNat, err := get.GetIptablesFirewall()
		if err != nil {
			return err
		}
		result = resNat
	}

	chainsFormat := `
name: %s
policy: %s
packets: %d
bytes: %d
`
	rulesFormat := "Rules: %d, Pkts: %d, Bytes: %d, Target: %s, " +
		"Prot: %s, Opt: %s, In: %s, Out: %s, Source: %s, " +
		"Destination: %s, Options: %s\n"

	for _, val := range result.Chains {
		fmt.Printf(
			chainsFormat,
			val.Name,
			val.Policy,
			val.Packets,
			val.Bytes,
		)
		if len(val.Rules) == 0 {
			fmt.Println("Rules: none")
		} else {
			for _, val := range val.Rules {

				if val.Options == "" {
					val.Options = "none"
				}

				fmt.Printf(
					rulesFormat,
					val.Id,
					val.Pkts,
					val.Bytes,
					val.Target,
					val.Prot,
					val.Opt,
					val.In,
					val.Out,
					val.Source,
					val.Destination,
					val.Options,
				)
			}
		}

	}
	fmt.Println()

	return nil
}

// Function to display Private and Public keys.
func printWgKey(p map[string]wgtypes.Key) {
	fmt.Printf(`
private_key: %s
public_key: %s

`,
		p["private"],
		p["public"],
	)
}
