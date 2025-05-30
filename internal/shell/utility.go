// Package describes the operation of the server's internal utilities.
package shell

type IpFlagString string

const (
	IpUp        IpFlagString = "up"
	IpDown      IpFlagString = "down"
	IpAdd       IpFlagString = "add"
	IpDel       IpFlagString = "del"
	IpTablesAdd IpFlagString = "A"
	IpTablesDel IpFlagString = "D"
)

const (
	// Add Rules.
	SysctlIpv4Up string = "sysctl -w net.ipv4.ip_forward=1"
	SysctlIpv6Up string = "sysctl -w net.ipv6.conf.all.forwarding=1"
	// Delete Rules.
	SysctlIpv4Down string = "sysctl -w net.ipv4.ip_forward=0"
	SysctlIpv6Down string = "sysctl -w net.ipv6.conf.all.forwarding=0"
	// Check Rules.
	SysctlIpv4Check string = "sysctl net.ipv4.ip_forward"
	SysctlIpv6Check string = "sysctl net.ipv6.conf.all.forwarding"
	// Execute Rules.
	SysctlRules string = "sysctl -p"
)

const (
	// Command: ip.
	IpJSON      string = "ip -j addr"
	IpBriefJSON string = "ip -j -br addr"

	// Command: iptables.
	IptablesFirewall string = "iptables -L -v -n"
	IptablesNat      string = "iptables -t nat -L -v"
)
