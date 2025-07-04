// Package for internal processing of Wireguard utilities.
package handlers

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl"
)

// Function for initializing the wgctrl client.
func InitWgCtlClient() (*wgctrl.Client, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("error: invalid configuration: %v", err)
	}

	return client, nil
}

// Function converts a port string to an integer.
// It returns an error if the string is not a valid number.
func CheckPort(port string) (int, error) {

	portInt, err := strconv.Atoi(port)
	if err != nil {
		return 0, fmt.Errorf(
			"error: invalid port value, port must be a valid number, %w",
			err,
		)
	}

	return portInt, nil
}

// Function to check the endpoint IP address.
func CheckEndPoint(host string) (*net.UDPAddr, error) {
	data := strings.Split(host, ":")

	if len(data) != 2 {
		return nil, fmt.Errorf(
			"error: invalid endpoint format '%s', expected format: "+
				"`IP-address:port` (e.g., `89.89.89.1:51820`",
			host,
		)
	}

	port, err := CheckPort(data[1])
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(data[0])
	if ip == nil {
		return nil, fmt.Errorf(
			"error: invalid IPv4 address: '%s' "+
				"example: `192.168.1.1`", data[0])
	}

	return &net.UDPAddr{
		IP:   ip,
		Port: port,
	}, nil
}

// Function to check allowed IP addresses.
func CheckAllowedIPs(ipAddr []string) ([]net.IPNet, error) {
	allowIps := make([]net.IPNet, 0, len(ipAddr))

	for _, ips := range ipAddr {
		_, ipnet, err := net.ParseCIDR(ips)
		if err != nil {
			return nil, fmt.Errorf(
				"error: invalid CIDR format for allowed IP address '%s' "+
					"example: 10.10.10.1/32",
				ips,
			)
		}
		allowIps = append(allowIps, *ipnet)
	}

	return allowIps, nil
}
