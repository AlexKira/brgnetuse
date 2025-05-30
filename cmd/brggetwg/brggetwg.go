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
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/AlexKira/brgnetuse/internal/help"
	"github.com/AlexKira/brgnetuse/src/get"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var DefaultErrorMessage string = fmt.Sprintf(
	"Arguments passed incorrectly. Ask for help: [%s]",
	help.HelpFlag,
)

// Main entry point.
func main() {
	if len(os.Args) < 2 || os.Args[1] == help.HelpFlag {
		help.BridgeGetWgHelp()
		return
	}

	switch os.Args[1] {
	case help.WgInterfaceFlag:
		if len(os.Args) == 4 {
			iface, _ := get.GetExistInterface(os.Args[2])
			if !iface {
				help.ErrorExitMessage(
					"",
					fmt.Sprintf(
						"error: Network interface `%s` not found",
						os.Args[2],
					),
				)
				os.Exit(help.ExitSetupFailed)
			}
			if os.Args[3] == help.IpAddressFlag {
				if err := printIP(os.Args[2]); err != nil {
					help.ErrorExitMessage(
						"",
						err.Error(),
					)
					os.Exit(help.ExitSetupFailed)
				}
			} else if os.Args[3] == help.PeerFlag {
				if err := printWgInterface(os.Args[2]); err != nil {
					help.ErrorExitMessage(
						"",
						err.Error(),
					)
					os.Exit(help.ExitSetupFailed)
				}
			} else {
				help.ErrorExitMessage(
					os.Args[1],
					DefaultErrorMessage,
				)
				os.Exit(help.ExitSetupFailed)
			}
		} else {
			help.ErrorExitMessage(
				os.Args[1],
				DefaultErrorMessage,
			)
			os.Exit(help.ExitSetupFailed)
		}

	case help.IpAddressFlag:
		if err := printIP(""); err != nil {
			help.ErrorExitMessage(
				"",
				err.Error(),
			)
			os.Exit(help.ExitSetupFailed)
		}

	case help.PeerFlag:
		if err := printWgInterface(""); err != nil {
			help.ErrorExitMessage(
				"",
				err.Error(),
			)
			os.Exit(help.ExitSetupFailed)
		}
	case help.ForwardingFlag:
		resultMap, err := get.GetIPvForwarding()
		if err != nil {
			help.ErrorExitMessage(
				"",
				err.Error(),
			)
			os.Exit(help.ExitSetupFailed)
		}

		printFw(resultMap)

	case help.FirewallFlag:
		if err := printRules(false); err != nil {
			help.ErrorExitMessage(
				"",
				err.Error(),
			)
			os.Exit(help.ExitSetupFailed)
		}
	case help.NatFlag:
		if err := printRules(true); err != nil {
			help.ErrorExitMessage(
				"",
				err.Error(),
			)
			os.Exit(help.ExitSetupFailed)
		}
	case help.PrivateKeyFlag:
		resultMap, err := get.GenerateKeys()
		if err != nil {
			help.ErrorExitMessage(
				"",
				err.Error(),
			)
			os.Exit(help.ExitSetupFailed)
		}

		printWgKey(resultMap)

	default:
		help.ErrorExitMessage(
			os.Args[1],
			DefaultErrorMessage,
		)
		os.Exit(help.ExitSetupFailed)
	}

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
	init := get.GetPeerStructure{
		InterfaceName: name,
	}

	devices, err := init.GetPeer()

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
interface: %s (%s)
 private_key: (hidden)
 public_key: %s 
 listening_port: %d

`
	fmt.Printf(
		interfaceFormat,
		d.Name,
		d.Type.String(),
		d.PublicKey.String(),
		d.ListenPort,
	)
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
peer: %s,
  endpoint: %s
  allowed_ips: %s
  latest_handshake: %s
  transfer: %d B received, %d B sent

`,
		p.PublicKey.String(),
		// TODO(mdlayher): get right endpoint with getnameinfo.
		p.Endpoint.String(),
		ipsString(p.AllowedIPs),
		p.LastHandshakeTime.String(),
		p.ReceiveBytes,
		p.TransmitBytes,
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
	rulesFormat := `Rules: %d, Pkts: %d, Bytes: %d, Target: %s, Prot: %s, Opt: %s, In: %s, Out: %s, Source: %s, Destination: %s
`

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
