// Package contains internal logic and processing of utilities before launch.
package shell

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// Function of executing commands in the system shell.
func ShellCommand(cmd string, shell bool) error {
	_, err := exec.LookPath(strings.Fields(cmd)[0])
	if err != nil {
		return fmt.Errorf("runtime error: [%s], %v", cmd, err)
	}

	run := exec.Command("/bin/bash", "-c", cmd)

	if shell {
		run.Stdout = os.Stdout
		run.Stderr = os.Stderr
	}

	err = run.Start()
	if err != nil {
		return fmt.Errorf("runtime error: [%s], %v", cmd, err)
	}

	err = run.Wait()
	if err != nil {
		return fmt.Errorf("runtime error: [%s], %v", cmd, err)
	}

	return nil
}

// Function executes a command in the system shell and returns the
// combined stdout and stderr output.
// Returns the output of the command as a *bytes.Buffer and an error, if any.
func ShellCommandOutput(cmd string) (*bytes.Buffer, error) {
	_, err := exec.LookPath(strings.Fields(cmd)[0])
	if err != nil {
		return nil, fmt.Errorf(
			"runtime error: command '%s' not found: %v", strings.Fields(cmd)[0],
			err,
		)
	}

	output, err := exec.Command("/bin/bash", "-c", cmd).CombinedOutput()
	if err != nil {
		replacer := strings.NewReplacer("\n", "", ".", "")
		return nil, fmt.Errorf(
			"runtime error: %s", replacer.Replace(
				fmt.Sprintf(
					"%s, %v",
					output,
					err,
				),
			),
		)
	}

	return bytes.NewBuffer(output), nil
}

// Function to get active Linux network interface.
func GetNetInterfaceNameLinux() string {
	schemaInterfaceNameLinux := map[string]int{
		// Ethernet
		"eth": 1,
		"enp": 1,
		"ens": 1,
		// Wi-Fi
		"wla": 1,
		"wlp": 1,
		"wlx": 1,
		// Virtual
		"vir": 1,
		"doc": 1,
		"vet": 1,
	}

	netIfaces, _ := net.Interfaces()
	for _, iface := range netIfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			ipSlice, _ := iface.Addrs()
			if len(iface.Name) >= 3 && len(ipSlice) > 0 {
				if schemaInterfaceNameLinux[iface.Name[:3]] == 1 {
					return iface.Name
				}
			}
		}
	}

	return ""
}

// Function generate the `ip` command when deleting.
func FormatCmdIpLinkDelete(iface string) string {
	return fmt.Sprintf("ip link delete %s", iface)
}

// Function generates the `ip` command to control the status of the network interface.
func FormatCmdIpLinkSet(iface string, flag IpFlagString) string {
	return fmt.Sprintf("ip link set %s %s", iface, flag)
}

// Function generates the `ip` command to add or remove an IP address.
func FormatCmdIpAddrDev(iface, ip string, flag IpFlagString) string {
	return fmt.Sprintf(
		"ip addr %s %s dev %s",
		flag,
		ip,
		iface,
	)
}

// Function generates an iptables command to manage (add/remove) an INGRESS
// rule for UDP traffic on the specified destination port.
func FormatCmdIptablesFirewallPort(flag IpFlagString, dport string) string {

	cmd := fmt.Sprintf(
		"iptables -%s INPUT -p udp --dport %s -j ACCEPT",
		flag, dport,
	)

	return cmd
}

// Function generates the `iptables` command to manage the firewall rules.
func FormatCmdIptablesFirewall(flag IpFlagString, osIface, wgIface string) string {

	in := fmt.Sprintf(
		"iptables -%s FORWARD -i %s -o %s -j ACCEPT",
		flag, osIface, wgIface,
	)

	out := fmt.Sprintf(
		"iptables -%s FORWARD -i %s -o %s -j ACCEPT",
		flag, wgIface, osIface,
	)
	cmd := fmt.Sprintf("%s && %s", in, out)
	return cmd
}

// Function generates the `iptables` command to manage the NAT rules.
func FormatCmdIptablesNat(flag IpFlagString, osIface, subnet string) string {
	cmd := fmt.Sprintf(
		"iptables -t nat -%s POSTROUTING -s %s -o %s -j MASQUERADE",
		flag, subnet, osIface,
	)
	return cmd
}

// Function constructs the 'ip link show' command for a given interface.
func FormatCmdIpShowJSON(iface string) string {
	return fmt.Sprintf("ip -j addr show %s", iface)
}

// Function creates the 'awg show <interface>' command string.
// This command is used to display the configuration and status of a specific WireGuard interface.
func FormatCmdAwgShow(iface string) string {
	return fmt.Sprintf("awg show %s", iface)
}

// Function creates the 'awg set <interface> listen-port <port>' command string.
// This command is used to update the listening port of a specific WireGuard interface.
func FormatCmdAwgUpdatePort(iface, port string) string {
	return fmt.Sprintf("awg set %s listen-port %s", iface, port)
}

// Function creates the 'awg set <interface> private-key <(echo '<privateKey>')' command string.
// This command is used to set the private key for a specific WireGuard interface using a secure shell redirection.
func FormatCmdAwgUpdatePrivateKey(iface, pk string) string {
	return fmt.Sprintf("awg set %s private-key <(echo '%s')", iface, pk)
}

// Function creates the 'awg set <interface> peer <publicKey> allowed-ips <allowedIPs> [persistent-keepalive <keepalive>] [endpoint <endpoint>]' command string.
// This command is used to add a new peer to a specified WireGuard interface,
// optionally including persistent keepalive and endpoint settings.
func FormatCmdAwgAddPeer(iface, pk, aips, kp, epoint string) string {
	cmd := fmt.Sprintf(
		"awg set %s peer '%s' allowed-ips %s ",
		iface, pk, aips,
	)
	if kp != "" {
		cmd += fmt.Sprintf("persistent-keepalive %s ", kp)
	}

	if epoint != "" {
		cmd += fmt.Sprintf("endpoint %s ", epoint)
	}

	return cmd
}

func FormatCmdAwgDeletePeer(iface, pk string) string {
	return fmt.Sprintf("awg set %s peer '%s' remove", iface, pk)
}
