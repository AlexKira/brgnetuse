// CLI Tool Management Information Package.
package help

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/AlexKira/brgnetuse/internal/handlers"
	"github.com/AlexKira/brgnetuse/src/get"
)

const RegexSymbols = `!@#$%^&*()_+-=}{][|'~?`

const Env_Field_Foreground = "WG_PROCESS_FOREGROUND"
const Env_Field_Type = "ENV_PROTOCOL_TYPE"
const Env_Field_Tag = "ENV_PROTOCOL_TAG"

const Env_Awg_Type string = "awg"
const Env_Wg_Type string = "wg"

const ExitSetupFailed int = 1

const (
	// Default flag.
	HelpFlag        string = "-h"
	WgInterfaceFlag string = "-i"
	AddFlag         string = "-a"
	DelFlag         string = "-d"
	PortFlag        string = "-p"
	UpdateFlag      string = "-u"
	LogTypeFlag     string = "-js"

	// Utility brgaddwg.
	PathLogDirFlag string = "-l"
	LogInfoFlag    string = "-ld"
	LogErrorFlag   string = "-le"
	MTUFlag        string = "-m"

	// Utility brgsetwg.
	IpAddressFlag          string = "-ip"
	EnableWgInterfaceFlag  string = "-up"
	DisableWgInterfaceFlag string = "-dw"
	NatFlag                string = "-n"
	ForwIpv4Flag           string = "-fw4"
	ForwIpv6Flag           string = "-fw6"
	PrivateKeyFlag         string = "-pk"
	PeerFlag               string = "-pr"
	KeepaliveFlag          string = "-kp"
	EndPointHostFlag       string = "-eh"

	// Utility brggetwg.
	ForwardingFlag string = "-fw"
	FirewallFlag   string = "-fr"
)

// Function prints a formatted help message to the console for the utility.
// It dynamically inserts the utility's name into the help text and examples.
func BridgeAddHelp(utility string) {
	fmt.Fprintln(os.Stderr, "┌────────────────────────────────────────────────────────────────────┐")
	fmt.Fprintln(os.Stderr, "│                                                                    │")
	fmt.Fprintf(os.Stderr, "│  Help using the utility: %s                                 │\n", utility)
	fmt.Fprintln(os.Stderr, "|  ______________________________________________________________    |")
	fmt.Fprintln(os.Stderr, "│                                                                    │")
	fmt.Fprintln(os.Stderr, "│    [-h]           Help.                                            │")
	fmt.Fprintln(os.Stderr, "│    |_[-i][name]   Add a network interface name.                    │")
	fmt.Fprintln(os.Stderr, "│    |_[-m][number] Add MTU size.                                    │")
	fmt.Fprintln(os.Stderr, "│    |_[-l][path]   Add path to log file directory.                  │")
	fmt.Fprintln(os.Stderr, "│        |_[-ld]    Logging level: Debug.                            │")
	fmt.Fprintln(os.Stderr, "│        |_[-le]    Logging level: Error.                            │")
	fmt.Fprintln(os.Stderr, "│        |_[-js]    Logging type JSON. Defailt: String.              │")
	fmt.Fprintln(os.Stderr, "│                                                                    │")
	fmt.Fprintln(os.Stderr, "│  Example:                                                          │")
	fmt.Fprintln(os.Stderr, "|  ______________________________________________________________    |")
	fmt.Fprintln(os.Stderr, "│                                                                    │")
	fmt.Fprintln(os.Stderr, "│   Add a network interface name:                                    │")
	fmt.Fprintf(os.Stderr, "│     %s -i wg0                                               │\n", utility)
	fmt.Fprintln(os.Stderr, "│                                                                    │")
	fmt.Fprintln(os.Stderr, "│   Add MTU size:                                                    │")
	fmt.Fprintf(os.Stderr, "│    %s -i wg0 -m 1340                                        │\n", utility)
	fmt.Fprintln(os.Stderr, "│                                                                    │")
	fmt.Fprintln(os.Stderr, "│   Add path to log file directory:                                  │")
	fmt.Fprintf(os.Stderr, "│     %s -i wg0 -l /var/log -ld                               │\n", utility)
	fmt.Fprintf(os.Stderr, "│     %s -i wg0 -l /var/log -le -js                           │\n", utility)
	fmt.Fprintf(os.Stderr, "│     %s -i wg0 -m 1340 -l /var/log -ld -js                   │\n", utility)
	fmt.Fprintln(os.Stderr, "│                                                                    │")
	fmt.Fprintln(os.Stderr, "└────────────────────────────────────────────────────────────────────┘")
}

// Function prints a comprehensive help message to the console for the `brgsetwg` utility.
// It details all available flags, their sub-commands, and provides numerous usage examples
// for configuring WireGuard interfaces, managing peers, IP addresses, firewall rules,
// and network forwarding. It also includes useful external commands for resetting firewall/NAT rules.
func BridgeSetWgHelp() {
	fmt.Fprintln(os.Stderr, "┌───────────────────────────────────────────────────────────────────────────────────────┐")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│  Help using the utility: brgsetwg.                                                    │")
	fmt.Fprintln(os.Stderr, "|  ___________________________________________________________________________________  |")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│  NOTE: This utility acts as a wrapper for the following tools:                        │")
	fmt.Fprintln(os.Stderr, "│        iptables, ip, and awg.                                                         │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│    [-h]                          Help.                                                │")
	fmt.Fprintln(os.Stderr, "│    |_[-i][name]                  Wireguard network interface name.                    │")
	fmt.Fprintln(os.Stderr, "│    |   |_[-d]                    Remove Wireguard Network Interface.                  │")
	fmt.Fprintln(os.Stderr, "│    |   |_[-up]                   Enable network interface.                            │")
	fmt.Fprintln(os.Stderr, "│    |   |_[-dw]                   Disable network interface.                           │")
	fmt.Fprintln(os.Stderr, "│    |   |                                                                              │")
	fmt.Fprintln(os.Stderr, "│    |   |_[-u]                                                                         │")
	fmt.Fprintln(os.Stderr, "│    |   |   |_[-p][number]        Update port.                                         │")
	fmt.Fprintln(os.Stderr, "│    |   |   |_[-pk]               Update private key Wireguard network interface.      │")
	fmt.Fprintln(os.Stderr, "│    |   |        |_[key]          Your private key in base64 encoding.                 │")
	fmt.Fprintln(os.Stderr, "│    |   |                                                                              │")
	fmt.Fprintln(os.Stderr, "│    |   |_[-pr][pub_key]          Add peer for the Wireguard network interface.        │")
	fmt.Fprintln(os.Stderr, "│    |   |    |_[-a][address]      Allowed IP address in CIDR notation.                 │")
	fmt.Fprintln(os.Stderr, "│    |   |    |_[-kp][number]      Persistent keepalive interval in seconds.            │")
	fmt.Fprintln(os.Stderr, "│    |   |    |_[-eh][address]     Endpoint host.                                       │")
	fmt.Fprintln(os.Stderr, "│    |   |                                                                              │")
	fmt.Fprintln(os.Stderr, "│    |   |_[-pr][pub_key][-d]      Delete peer for the Wireguard network interface.     │")
	fmt.Fprintln(os.Stderr, "│    |   |                                                                              │")
	fmt.Fprintln(os.Stderr, "│    |   |_[-ip][address]          IP address in CIDR notation.                         │")
	fmt.Fprintln(os.Stderr, "│    |        |_[-a]               Add IP address for network interface.                │")
	fmt.Fprintln(os.Stderr, "│    |        |   |                                                                     │")
	fmt.Fprintln(os.Stderr, "│    |        |   |_[-n] or [-fr]  Automatically add NAT rules.                         │")
	fmt.Fprintln(os.Stderr, "│    |        |          |_[name]  Network interface name.                              │")
	fmt.Fprintln(os.Stderr, "│    |        |                                                                         │")
	fmt.Fprintln(os.Stderr, "│    |        |_[-d]               Delete IP address of network interface.              │")
	fmt.Fprintln(os.Stderr, "│    |            |_[-n]           Delete NAT rules.                                    │")
	fmt.Fprintln(os.Stderr, "│    |            |   |_[name]     Network interface name.                              │")
	fmt.Fprintln(os.Stderr, "│    |            |                                                                     │")
	fmt.Fprintln(os.Stderr, "│    |            |_[-fr]          Delete Firewall rules.                               │")
	fmt.Fprintln(os.Stderr, "│    |                |_[name]     Network interface name.                              │")
	fmt.Fprintln(os.Stderr, "│    |                                                                                  │")
	fmt.Fprintln(os.Stderr, "│    |_[-fw4]                      Forwarding `IPV4` between network interfaces.        │")
	fmt.Fprintln(os.Stderr, "│    |    |_[-a]                   Enable.                                              │")
	fmt.Fprintln(os.Stderr, "│    |    |_[-d]                   Disable.                                             │")
	fmt.Fprintln(os.Stderr, "│    |                                                                                  │")
	fmt.Fprintln(os.Stderr, "│    |_[-fw6]                      Forwarding `IPV6` between network interfaces.        │")
	fmt.Fprintln(os.Stderr, "│    |    |_[-a]                   Enable.                                              │")
	fmt.Fprintln(os.Stderr, "│    |    |_[-d]                   Disable.                                             │")
	fmt.Fprintln(os.Stderr, "│    |                                                                                  │")
	fmt.Fprintln(os.Stderr, "│    |_[-fr]                       Additional Firewall Commands.                        │")
	fmt.Fprintln(os.Stderr, "│         |_[-u]                   Type: UDP.                                           │")
	fmt.Fprintln(os.Stderr, "│             |_[-a][number]       Add port number to table.                            │")
	fmt.Fprintln(os.Stderr, "│             |_[-d][number]       Delete port number from table.                       │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│  Example:                                                                             │")
	fmt.Fprintln(os.Stderr, "|  ___________________________________________________________________________________  |")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│   Remove Wireguard Network Interface:                                                 │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -i wg0 -d                                                                │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│   Enable network interface:                                                           │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -i wg0 -up                                                               │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│   Disable network interface:                                                          │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -i wg0 -dw                                                               │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│   Update port:                                                                        │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -i wg0 -u -p 51855                                                       │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│   Update private key Wireguard network interface:                                     │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -i wg0 -u -pk                                                            │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -i wg0 -u -pk AAAAAAAAAAAAA=                                             │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│   Add peer for the Wireguard network interface:                                       │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -i wg0 -pr AAAAAAAAAAAAA= -a 10.0.0.1/32                                 │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -i wg0 -pr AAAAAAAAAAAAA= -a 10.0.0.1/32 -kp 10 -eh 172.168.85.1:65535   │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│   Delete peer for the Wireguard network interface:                                    │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -i wg0 -pr AAAAAAAAAAAAA= -d                                             │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│   Add IP address for network interface:                                               │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -i wg0 -ip 10.10.10.254/24 -a                                            │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│   Delete IP address of network interface:                                             │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -i wg0 -ip 10.10.10.254/24 -d                                            │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│   Adding NAT rules to the active default network interface:                           │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -i wg0 -ip 10.10.10.0/24 -a -n                                           │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│   Adding NAT rules by network interface name:                                         │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -i wg0 -ip 10.10.10.0/24 -a -n enp0s3                                    │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│   Delete NAT rules for the active default network interface:                          │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -i wg0 -ip 10.10.10.0/24 -d -n                                           │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│   Delete NAT rules by network interface name:                                         │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -i wg0 -ip 10.10.10.0/24 -d -n enp0s3                                    │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│   Delete firewall rules for the active default network interface:                     │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -i wg0 -ip 10.10.10.0/24 -d -fr                                          │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│   Delete Firewall rules by network interface name:                                    │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -i wg0 -ip 10.10.10.0/24 -d -fr enp0s3                                   │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│   Forwarding `IPV4` between network interfaces:                                       │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -fw4 -a                                                                  │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -fw4 -d                                                                  │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│   Forwarding `IPV6` between network interfaces:                                       │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -fw6 -a                                                                  │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -fw6 -d                                                                  │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│   Command to add a UDP port rule to the firewall:                                     │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -fr -u -a 51820                                                          │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│   Command to drop a UDP port rule in the firewall:                                    │")
	fmt.Fprintln(os.Stderr, "│     brgsetwg -fr -u -d 51820                                                          │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│  Useful commands:                                                                     │")
	fmt.Fprintln(os.Stderr, "|  ___________________________________________________________________________________  |")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│  Firewall: reset rules default.                                                       │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│      Resets (removes) all rules, documents in the filter table:                       │")
	fmt.Fprintln(os.Stderr, "│        iptables -F                                                                    │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│      Removes all non-standard (user-created) chains in the filter table:              │")
	fmt.Fprintln(os.Stderr, "│        iptables -X                                                                    │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│      Sets the default policy for the INPUT chain in the filter table to ACCEPT:       │")
	fmt.Fprintln(os.Stderr, "│        iptables -P INPUT ACCEPT                                                       │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│      Sets the default policy for the FORWARD chain in the filter table to ACCEPT:     │")
	fmt.Fprintln(os.Stderr, "│        iptables -P FORWARD ACCEPT                                                     │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│      Sets the default policy for the OUTPUT chain in the filter table to ACCEPT:      │")
	fmt.Fprintln(os.Stderr, "│         iptables -P OUTPUT ACCEPT                                                     │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│  NAT: reset rules default.                                                            │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│     Resets (removes) all rules:                                                       │")
	fmt.Fprintln(os.Stderr, "│       iptables -t nat -F                                                              │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│     Deletes all non-standard (user created) chains:                                   │")
	fmt.Fprintln(os.Stderr, "│       iptables -t nat -X                                                              │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│     Sets the default policy for the PREROUTING chain:                                 │")
	fmt.Fprintln(os.Stderr, "│       iptables -t nat -P PREROUTING ACCEPT                                            │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│     Sets the default policy for the INPUT chain:                                      │")
	fmt.Fprintln(os.Stderr, "│       iptables -t nat -P INPUT ACCEPT                                                 │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│     Sets the default policy for the OUTPUT chain:                                     │")
	fmt.Fprintln(os.Stderr, "│       iptables -t nat -P OUTPUT ACCEPT                                                │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "│     Sets the default policy for the POSTROUTING chain:                                │")
	fmt.Fprintln(os.Stderr, "│       iptables -t nat -P POSTROUTING ACCEPT                                           │")
	fmt.Fprintln(os.Stderr, "│                                                                                       │")
	fmt.Fprintln(os.Stderr, "└───────────────────────────────────────────────────────────────────────────────────────┘")
}

// Function prints a help message to the console for the `brggetwg` utility.
// It outlines flags for retrieving WireGuard interface settings (IPs, peers),
// global network configurations (forwarding, firewall, NAT rules),
// and provides an option to generate new WireGuard key pairs.
func BridgeGetWgHelp() {
	fmt.Fprintln(os.Stderr, "┌──────────────────────────────────────────────────────────────────────┐")
	fmt.Fprintln(os.Stderr, "│                                                                      │")
	fmt.Fprintln(os.Stderr, "│  Help using the utility: brggetwg.                                   │")
	fmt.Fprintln(os.Stderr, "|  __________________________________________________________________  |")
	fmt.Fprintln(os.Stderr, "│                                                                      │")
	fmt.Fprintln(os.Stderr, "│  NOTE: This utility acts as a wrapper for the following tools:       │")
	fmt.Fprintln(os.Stderr, "│        iptables, ip, and awg.                                        │")
	fmt.Fprintln(os.Stderr, "│                                                                      │")
	fmt.Fprintln(os.Stderr, "│    [-h]           Help.                                              │")
	fmt.Fprintln(os.Stderr, "│    |_[-i][name]   Wireguard network interface name.                  │")
	fmt.Fprintln(os.Stderr, "│    |   |_[-ip]    Get IP settings for a network interface.           │")
	fmt.Fprintln(os.Stderr, "│    |   |_[-pr]    Get peer settings for a network interface.         │")
	fmt.Fprintln(os.Stderr, "│    |                                                                 │")
	fmt.Fprintln(os.Stderr, "│    |_[-ip]        Get all IP settings for all network interfaces.    │")
	fmt.Fprintln(os.Stderr, "│    |_[-pr]        Get all peer settings for all network interfaces.  │")
	fmt.Fprintln(os.Stderr, "│    [_[-fw]        Get IPv4 and IPv6 forwarding settings.             │")
	fmt.Fprintln(os.Stderr, "│    |_[-fr]        Get all firewall rules.                            │")
	fmt.Fprintln(os.Stderr, "│    |_[-n]         Get all NAT rules.                                 │")
	fmt.Fprintln(os.Stderr, "│    |                                                                 │")
	fmt.Fprintln(os.Stderr, "│    |_[-pk]        Generate Public and Private Keys (Base64 encoded). │")
	fmt.Fprintln(os.Stderr, "│                                                                      │")
	fmt.Fprintln(os.Stderr, "│  Example:                                                            │")
	fmt.Fprintln(os.Stderr, "|  __________________________________________________________________  |")
	fmt.Fprintln(os.Stderr, "│                                                                      │")
	fmt.Fprintln(os.Stderr, "│   Wireguard network interface name:                                  │")
	fmt.Fprintln(os.Stderr, "│     brggetwg -i wg0 -ip                                              │")
	fmt.Fprintln(os.Stderr, "│                                                                      │")
	fmt.Fprintln(os.Stderr, "│   Get peer settings for a network interface:                         │")
	fmt.Fprintln(os.Stderr, "│     brggetwg -i wg0 -pr                                              │")
	fmt.Fprintln(os.Stderr, "│                                                                      │")
	fmt.Fprintln(os.Stderr, "│   Get all IP settings for all network interfaces:                    │")
	fmt.Fprintln(os.Stderr, "│     brggetwg -ip                                                     │")
	fmt.Fprintln(os.Stderr, "│                                                                      │")
	fmt.Fprintln(os.Stderr, "│   Get all peer settings for all network interfaces:                  │")
	fmt.Fprintln(os.Stderr, "│     brggetwg -pr                                                     │")
	fmt.Fprintln(os.Stderr, "│                                                                      │")
	fmt.Fprintln(os.Stderr, "│   Get IPv4 and IPv6 forwarding settings:                             │")
	fmt.Fprintln(os.Stderr, "│     brggetwg -fw                                                     │")
	fmt.Fprintln(os.Stderr, "│                                                                      │")
	fmt.Fprintln(os.Stderr, "│   Get all firewall rules:                                            │")
	fmt.Fprintln(os.Stderr, "│     brggetwg -fr                                                     │")
	fmt.Fprintln(os.Stderr, "│                                                                      │")
	fmt.Fprintln(os.Stderr, "│   Get all NAT rules:                                                 │")
	fmt.Fprintln(os.Stderr, "│     brggetwg -n                                                      │")
	fmt.Fprintln(os.Stderr, "│                                                                      │")
	fmt.Fprintln(os.Stderr, "│   Generate Public and Private Keys (Base64 encoded):                 │")
	fmt.Fprintln(os.Stderr, "│     brggetwg -pk                                                     │")
	fmt.Fprintln(os.Stderr, "│                                                                      │")
	fmt.Fprintln(os.Stderr, "└──────────────────────────────────────────────────────────────────────┘")
}

// DefaultErrorMessage provides a standard message for
// incorrect arguments, prompting users to seek help.
var DefaultErrorMessage string = fmt.Sprintf(
	"error: arguments passed incorrectly, ask for help: '%s'",
	HelpFlag,
)

// Function for outputting error information to the console.
func ErrorExitMessage(flag, msg string) {
	if flag != "" {
		fmt.Printf("error: invalid input parameter: '%s'\n", flag)
	}
	fmt.Printf("%s\n", msg)
}

// Function to check for a valid WireGuard interface name.
func WgInterfaceNameValid(flag, name string) string {
	var msg string

	if strings.ContainsAny(name, RegexSymbols) {
		msg = fmt.Sprintf(
			"error: invalid character in interface name '%s'. Example: wg0, wg1",
			name,
		)
		ErrorExitMessage(flag, msg)
		os.Exit(ExitSetupFailed)
	}

	result, err := get.GetExistInterface(name)
	if err != nil {
		ErrorExitMessage(
			EnableWgInterfaceFlag,
			fmt.Sprintf(
				"error: failed getting network interfaces '%s', %v",
				name,
				err,
			))
		os.Exit(ExitSetupFailed)

	}
	if result {
		ErrorExitMessage(
			WgInterfaceFlag,
			fmt.Sprintf(
				"error: network interface name '%s' already exists",
				name,
			),
		)
		os.Exit(ExitSetupFailed)
	}
	return name
}

// Function to check for a valid WireGuard interface name.
func PortValid(flag, port string) string {
	re := regexp.MustCompile(`^\d+$`)
	if strings.ContainsAny(port, RegexSymbols) || !re.MatchString(port) {
		msg := fmt.Sprintf(
			"error: port must not contain symbols '%s', example: 51820, 51821",
			port,
		)
		ErrorExitMessage(flag, msg)
		os.Exit(ExitSetupFailed)
	}

	_, err := handlers.CheckPort(port)
	if err != nil {
		ErrorExitMessage(flag, err.Error())
		os.Exit(ExitSetupFailed)
	}
	return port
}

// Function for checking the validity of WireGuard port range.
func PathLogDirValid(flag, path string) string {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		msg := fmt.Sprintf(
			"error: `%s` does not exist",
			path,
		)
		ErrorExitMessage(flag, msg)
		os.Exit(ExitSetupFailed)
	}
	return path
}

// Function to check IP address.
func IpAddressValid(flag, address string) (net.IP, *net.IPNet) {
	ip, ipnet, err := net.ParseCIDR(address)
	if err != nil {
		ErrorExitMessage(
			flag,
			fmt.Sprintf(
				"error: invalid IP address format '%s' example: 10.10.10.1/24",
				address,
			),
		)
		os.Exit(ExitSetupFailed)
	}

	return ip, ipnet
}

// Function scans all running processes to determine if any process
// has a specific environment variable (tag) set to a given value.
// It returns true if such a process is found, otherwise false.
// An error is returned only if there's a problem reading the /proc directory.
func CheckProcessTagExists(tag, wgType string) (bool, error) {

	valueTag := fmt.Sprintf("%s=%s", Env_Field_Tag, tag)
	valueType := fmt.Sprintf("%s=%s", Env_Field_Type, wgType)

	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return false, fmt.Errorf("error: could not read directory /proc: %w", err)
	}

	for _, subdir := range dirs {
		pid, err := strconv.Atoi(subdir.Name())
		if err != nil {
			continue
		}

		fmtEnvPath := fmt.Sprintf("/proc/%d/environ", pid)
		environContent, err := os.ReadFile(fmtEnvPath)
		if err != nil {
			continue
		}

		envStr := string(environContent)

		if strings.Contains(envStr, valueTag) && strings.Contains(envStr, valueType) {
			return true, nil
		}

	}

	return false, nil
}
