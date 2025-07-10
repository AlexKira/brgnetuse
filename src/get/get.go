// Package provides functions for retrieving information about the state of WireGuard nodes,
// NAT, and Firewall network interfaces.
package get

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/AlexKira/brgnetuse/internal/handlers"
	"github.com/AlexKira/brgnetuse/internal/shell"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Function parses the raw string output of the 'iptables -L -v -n'
// command and populates an IptablesOutput structure with the parsed data.
//
// This function iterates through each line of the iptables
// output, identifying chain definitions and rule entries.
// It extracts relevant information such as chain names,
// policies, packet counts, byte counts, rule targets, protocols,
// and source/destination addresses, and stores them in the
// IptablesOutput structure.
//
// Returns:
//   - IptablesOutput: A structure representing the parsed iptables data.
//   - error: An error if parsing fails, or nil if successful.
func parseIptablesOutput(output string) (IptablesOutput, error) {
	var result IptablesOutput

	parseInt := func(s string) int {
		var num int
		_, err := fmt.Sscanf(s, "%d", &num)
		if err != nil {
			return 0
		}
		return num
	}

	lines := strings.Split(output, "\n")
	var currentChain *IptablesChain

	ruleIdCounter := uint64(1)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "pkts") {
			continue
		}

		if strings.HasPrefix(line, "Chain ") {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}

			chainName := parts[1]
			chain := IptablesChain{Name: chainName}

			if len(parts) >= 7 && parts[2] == "(policy" {
				chain.Policy = parts[3]
				chain.Packets = parseInt(parts[4])
				chain.Bytes = parseInt(strings.TrimSuffix(parts[6], ")"))
			} else if len(parts) >= 4 && strings.Contains(parts[2], "references") {
				refStr := strings.TrimPrefix(parts[2], "(")
				refStr = strings.TrimSuffix(refStr, "references)")
				chain.References = parseInt(refStr)
			}

			result.Chains = append(result.Chains, chain)
			currentChain = &result.Chains[len(result.Chains)-1]
		} else if currentChain != nil {
			parts := strings.Fields(line)
			if len(parts) >= 8 {
				rule := IptablesRule{
					Id:          ruleIdCounter,
					Pkts:        parseInt(parts[0]),
					Bytes:       parseInt(parts[1]),
					Target:      parts[2],
					Prot:        parts[3],
					Opt:         parts[4],
					In:          parts[5],
					Out:         parts[6],
					Source:      parts[7],
					Destination: parts[8],
				}

				if len(parts) >= 9 {
					rule.Options = strings.Join(parts[9:], " ")
				}

				currentChain.Rules = append(currentChain.Rules, rule)
				ruleIdCounter++
			}
		}
	}

	return result, nil
}

// Function for сhecking network interface.
func GetExistInterface(name string) (bool, error) {
	interfaceName, err := net.Interfaces()
	if err != nil {
		return false, fmt.Errorf(
			"error: failed to get network interfaces: %s",
			err.Error(),
		)
	}

	for _, ifaces := range interfaceName {
		if ifaces.Name == name {
			return true, nil
		}
	}
	return false, nil
}

// GetIpNetInterface finds the IP addresses of the network interface with the given name.
//
// The 'name' argument is the interface name (e.g., "eth0").
//
// Returns:
//   - The number of IP addresses found (int).
//   - A slice of net.Addr containing the IP addresses.
//   - An error (error) if a problem occurred or the interface was not found (nil on success).
func GetIpNetInterface(name string) (int, []net.Addr, error) {
	netIface, err := net.Interfaces()
	if err != nil {
		return -1, nil, fmt.Errorf(
			"error: failed to get network interfaces. %v", err.Error())
	}
	for _, iface := range netIface {

		ipSlice, err := iface.Addrs()
		if err != nil {
			return -1, nil, fmt.Errorf(
				"error: failed to get IP address for interface '%s'. %s",
				iface.Name,
				err.Error(),
			)
		}

		if iface.Name == name {
			return len(ipSlice), ipSlice, nil
		}
	}

	return -1, nil, fmt.Errorf(
		"error: network interface '%s' not found", name,
	)
}

// Function generates key pair (private and public).
// It returns a map containing the keys, or an error if generation fails.
// The map keys are "private" and "public".
func GenerateKeys() (map[string]wgtypes.Key, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()

	keysMap := map[string]wgtypes.Key{
		"private": privateKey,
		"public":  privateKey.PublicKey(),
	}

	return keysMap, err
}

// Function retrieves information about network interfaces and their IP addresses.
// It executes the 'ip -j addr' command and returns a slice of IpInterfaceStructure.
func GetIp() ([]IpInterfaceStructure, error) {
	output, err := shell.ShellCommandOutput(shell.IpJSON)
	if err != nil {
		return nil, err
	}

	jsonData := output.Bytes()

	var interfaces []IpInterfaceStructure
	err = json.Unmarshal(jsonData, &interfaces)
	if err != nil {
		return nil, fmt.Errorf("error: failed to unmarshal JSON, %v", err)
	}

	return interfaces, nil
}

// Function retrieves IP address information for a specific network interface.
// It executes the 'ip -j link show' command and returns a slice of IpInterfaceStructure.
func GetIpShow(interfaceName string) ([]IpInterfaceStructure, error) {
	output, err := shell.ShellCommandOutput(shell.FormatCmdIpShowJSON(interfaceName))
	if err != nil {
		return nil, err
	}

	jsonData := output.Bytes()

	var interfaces []IpInterfaceStructure
	err = json.Unmarshal(jsonData, &interfaces)
	if err != nil {
		return nil, fmt.Errorf(
			"error: failed to unmarshal JSON for interface '%s', %v",
			interfaceName,
			err,
		)
	}

	return interfaces, nil
}

// Function retrieves and parses the output of the iptables command.
// It returns an IptablesOutput structure representing the firewall rules.
func GetIptablesFirewall() (IptablesOutput, error) {
	output, err := shell.ShellCommandOutput(shell.IptablesFirewall)
	if err != nil {
		return IptablesOutput{}, err
	}

	iptablesOutput, err := parseIptablesOutput(output.String())
	if err != nil {
		return IptablesOutput{}, fmt.Errorf("error: %s", err.Error())
	}
	return iptablesOutput, nil
}

// Function retrieves and parses the output of the iptables NAT table.
// It returns an IptablesOutput structure representing the NAT rules.
func GetIptablesNAT() (IptablesOutput, error) {
	output, err := shell.ShellCommandOutput(shell.IptablesNat)
	if err != nil {
		return IptablesOutput{}, err
	}

	iptablesOutput, err := parseIptablesOutput(output.String())
	if err != nil {
		return IptablesOutput{}, fmt.Errorf("error: %s", err.Error())
	}
	return iptablesOutput, nil
}

// FilterIptablesOutput is the top-level structure that encapsulates the parsed
// output of the iptables command. It contains a single field, 'Rule', which
// holds the detailed information about the iptables rules organized into chains.
// This structure serves as a container for the entire firewall rule set.
type FilterIptablesOutput struct {
	Rule IptablesOutput
}

// Method retrieves a specific iptables rule by its ID.
// It iterates through the chains and their rules, and if a rule with the given
// ID is found, it returns a new IptablesOutput containing only that rule.
// If no rule with the specified ID is found, it returns an empty IptablesOutput
// and an error. The search for the rule is performed based on the 'Id' field of
// the IptablesRule. The function operates on a copy of the FilterIptablesOutput
// to avoid modifying the original data.
func (p *FilterIptablesOutput) GetRuleId(id int) (IptablesOutput, error) {

	if id <= 0 {
		return IptablesOutput{}, fmt.Errorf("error: rule 'id:%d' must be > 0", id)
	}

	copied := *p
	copied.Rule.Chains = make([]IptablesChain, len(p.Rule.Chains))

	var currentTableRules []IptablesRule
	var foundChainIndex int = -1

	for indx, value := range p.Rule.Chains {

		if len(value.Rules) == 0 {
			continue
		}

		if uint64(id) <= p.Rule.Chains[indx].Rules[len(p.Rule.Chains[indx].Rules)-1].Id {
			copied.Rule.Chains[indx].Name = value.Name
			copied.Rule.Chains[indx].Bytes = value.Bytes
			copied.Rule.Chains[indx].Policy = value.Policy
			copied.Rule.Chains[indx].Packets = value.Packets

			foundChainIndex = indx
			currentTableRules = value.Rules
			break
		}

	}

	if foundChainIndex == -1 {
		return IptablesOutput{}, fmt.Errorf("error: rule 'id:%d' not found", id)
	}

	if len(currentTableRules) > 0 {
		for _, rule := range currentTableRules {
			if rule.Id == uint64(id) {
				copied.Rule.Chains[foundChainIndex].Rules = append(
					copied.Rule.Chains[foundChainIndex].Rules, rule)
			}
		}
	}

	return copied.Rule, nil

}

// Method checks if an iptables rule with the specified input interface,
// output interface, and source subnet exists within the FilterIptablesOutput.
// It iterates over all chains and their rules, looking for a rule where the input
// interface matches (or is "any"), the output interface matches, and the source subnet
// matches (or is "0.0.0.0/0") the given parameters.
// Returns true if such a rule is found, false otherwise. Returns an error if the subnetCIDR is invalid.
func (p *FilterIptablesOutput) GetExistingRules(inIface, outIface, subnetCIDR string) (bool, error) {

	_, _, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return false, fmt.Errorf("error: invalid IP address format: %s", subnetCIDR)
	}

	for _, chain := range p.Rule.Chains {
		for _, existingRule := range chain.Rules {

			inMatch := existingRule.In == inIface || existingRule.In == "any"
			outMatch := existingRule.Out == outIface
			subnetMatch := existingRule.Source == subnetCIDR || existingRule.Source == "0.0.0.0/0"

			if inMatch && outMatch && subnetMatch {
				return true, nil
			}
		}

	}

	return false, nil
}

// Method checks whether the specified port exists in the options of iptables rules.
//
// The function takes the port as a string and verifies that it is a number.
// It then iterates over all chains and their rules,
// returning true if the port is found in the Options field of any rule.
// If the port string cannot be converted to a number, an error is returned.
// If the port is not found, the function returns false without an error.
func (p *FilterIptablesOutput) GetExistingPort(port string) (bool, error) {

	if _, err := strconv.Atoi(port); err != nil {
		return false, fmt.Errorf("error: port must be a number, %v", err)
	}

	for _, chain := range p.Rule.Chains {
		for _, rule := range chain.Rules {
			if strings.Contains(rule.Options, port) {
				return true, nil
			}
		}
	}

	return false, nil
}

// Function retrieves the IPv4 and IPv6 forwarding status from sysctl.
//
// It executes sysctl commands to check the values of "net.ipv4.ip_forward" and
// "net.ipv6.conf.all.forwarding". The function returns a map where the keys are
// "ipv4" and "ipv6", and the values are integers representing the forwarding status
// (1 for enabled, 0 for disabled). An error is returned if any issue occurs during
// command execution or parsing of the output.
func GetIPvForwarding() (map[string]int, error) {
	sysctlMap := make(map[string]int)
	cmdSlice := [2]string{shell.SysctlIpv4Check, shell.SysctlIpv6Check}

	keys := []string{"ipv4", "ipv6"}

	for i, cmd := range cmdSlice {
		output, err := shell.ShellCommandOutput(cmd)
		if err != nil {
			return nil, err
		}

		parts := strings.SplitN(strings.TrimSpace(output.String()), "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("error: invalid sysctl output: %s", output.String())
		}

		value, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("error: invalid sysctl value: %s", parts[1])
		}

		sysctlMap[keys[i]] = value
	}

	return sysctlMap, nil
}

// Function retrieves WireGuard device information.
// If interfaceName is specified, it returns information for that specific interface.
// Otherwise, it returns information for all WireGuard devices.
//
// Returns a slice of pointers to wgtypes.Device and an error, if any.
//
// Usage example:
//
//	devices, err := GetPeer()
//	if err != nil {
//	    // Handle error
//	}
//
//	for _, device := range devices {
//	    fmt.Println("Device:", device.Name)
//	    for _, peer := range device.Peers {
//	        fmt.Println("  Peer:", peer.PublicKey.String())
//	        // Additional processing
//	    }
//	}
func GetPeer(interfaceName string) ([]*wgtypes.Device, error) {
	newClient, err := handlers.InitWgCtlClient()
	if err != nil {
		return nil, fmt.Errorf("error: failed to open wgctrl, %v", err)
	}
	defer newClient.Close()

	var devices []*wgtypes.Device

	if interfaceName != "" {
		device, err := newClient.Device(interfaceName)
		if err != nil {
			return nil, fmt.Errorf("error: failed to get device %q, %v", interfaceName, err)
		}
		devices = append(devices, device)
	} else {
		devices, err = newClient.Devices()
		if err != nil {
			return nil, fmt.Errorf("error: failed to get devices, %v", err)
		}
	}

	return devices, nil
}
