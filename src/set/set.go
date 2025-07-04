// Package provides a set of ready-made functions for working with
// the Wireguard network.

package set

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/AlexKira/brgnetuse/internal/handlers"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Method generates and sets a new private key for the specified
// WireGuard network interface.
//
// If the PrivateKey field in the UpdatePrivateKeyStructure is empty,
// a new private key is generated.
//
// Otherwise, the provided PrivateKey (base64 encoded) is parsed and used.
//
// Returns:
//   - nil if the private key was successfully updated.
//   - An error if the private key generation or application failed
//     (e.g., invalid interface name, permission issues, invalid private key).
//
// Usage example:
//
//	args := set.UpdatePrivateKeyStructure{
//	    InterfaceName: "wg0",
//	    PrivateKey:    "", // or a base64 encoded private key
//	}
//
//	err := set.UpdatePrivateKey(args)
//	if err != nil {
//	    // Handle error
//	}
func UpdatePrivateKey(args UpdatePrivateKeyStructure) error {

	if args.InterfaceName == "" {
		return fmt.Errorf("error: failed to get Wireguard network interface name")
	}

	var pvKey wgtypes.Key

	if args.PrivateKey == "" {
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf(
				"error: %v",
				err,
			)
		}
		pvKey = key
	} else {
		key, err := wgtypes.ParseKey(args.PrivateKey)
		if err != nil {
			return fmt.Errorf(
				"error: %v",
				err,
			)
		}
		pvKey = key
	}

	newClient, err := handlers.InitWgCtlClient()
	if err != nil {
		return err
	}
	defer newClient.Close()

	config := wgtypes.Config{}
	config.PrivateKey = &pvKey

	err = newClient.ConfigureDevice(args.InterfaceName, config)
	if err != nil {
		return fmt.Errorf(
			"error: failed to update network interface '%s': %v",
			args.InterfaceName,
			err,
		)
	}
	return nil
}

// Method updates the listening port for the specified WireGuard network interface.
//
// **Parameters:**
//
//	interfaceName: The name of the WireGuard network interface.
//	port: The new listening port number (as a string).
//
// **Returns:**
//
//	nil if the port was successfully updated.
//	an error if the port is invalid or the update failed
func UpdatePort(interfaceName string, port string) error {

	portInt, err := handlers.CheckPort(port)
	if err != nil {
		return err
	}

	config := wgtypes.Config{}
	config.ListenPort = &portInt

	newClient, err := handlers.InitWgCtlClient()
	if err != nil {
		return err
	}
	defer newClient.Close()

	err = newClient.ConfigureDevice(interfaceName, config)
	if err != nil {
		return fmt.Errorf(
			"error: failed to update network interface '%s': %v",
			interfaceName,
			err,
		)
	}
	return nil
}

// Method adds or replaces the WireGuard peer configuration.
//
// **Parameters:**
//
//	replace: If true, the existing peer configuration with the same public key
//	         will be replaced. If false, a new peer will be added.
//
// **Returns:**
//
//	An error if the configuration cannot be applied, such as:
//	  - Invalid interface name.
//	  - Invalid public key or AllowedIPs.
//	  - Insufficient permissions to execute 'wg set'.
//	  - Error executing 'wg set'.
//
// **Usage examples:**
//
// ```go`
//
//	cfg := set.SinglePeerStructure{
//	    InterfaceName: "wg0",
//	    PublicKey:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
//	    AllowedIPs:    []string{"10.10.10.3/32", "10.10.10.2/32"},
//	}
//
// //Add a new peer without replacing existing ones.
//
//	err := cfg.AddPeer(false)
//	if err != nil {
//	    // Handle error
//	}
//
// //Replace an existing peer with the same public key.
//
//	err = cfg.AddPeer(true)
//	if err != nil {
//	    // Handle error
//	}
//
// ````
func (p *SinglePeerStructure) AddPeer(replace bool) error {
	if p.InterfaceName == "" {
		return fmt.Errorf("error: failed to get Wireguard network interface name")
	}

	if p.PublicKey == "" {
		return fmt.Errorf("error: failed to get public key for peer")
	}

	var endpoint *net.UDPAddr
	var duration time.Duration

	// Check and parse EndpointHost (optional).
	if p.EndpointHost != "" {
		host, err := handlers.CheckEndPoint(p.EndpointHost)
		if err != nil {
			return err
		}
		endpoint = host
	}

	// Check and parse PersistentKeepaliveInterval (optional).
	if p.PersistentKeepaliveInterval != "" {

		num, err := strconv.Atoi(p.PersistentKeepaliveInterval)

		if err != nil {
			return fmt.Errorf(
				"error: unable to get KeepAlive interval value %v",
				err,
			)
		}

		if num < 0 {
			num = 0
		}

		tm, err := time.ParseDuration(fmt.Sprintf("%ds", num))
		if err != nil {
			return fmt.Errorf("error: %v", err)
		}
		duration = tm
	}

	// Parse PublicKey (mandatory).
	pubKey, err := wgtypes.ParseKey(p.PublicKey)
	if err != nil {
		return fmt.Errorf("error: %v", err)
	}

	// Parse AllowedIPs (optional).
	alwIps, err := handlers.CheckAllowedIPs(p.AllowedIPs)
	if err != nil {
		return err
	}

	config := wgtypes.Config{
		ReplacePeers: replace,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:                   pubKey,
				AllowedIPs:                  alwIps,
				Endpoint:                    endpoint,
				PersistentKeepaliveInterval: &duration,
			},
		},
	}

	// Apply configuration.
	newClient, err := handlers.InitWgCtlClient()
	if err != nil {
		return err
	}
	defer newClient.Close()

	err = newClient.ConfigureDevice(p.InterfaceName, config)
	if err != nil {
		return fmt.Errorf(
			"error: failed to update network interface '%s': %v",
			p.InterfaceName, err,
		)
	}

	return nil
}

// Method removes a WireGuard peer from the configuration using the 'wg set' command.
//
// This method requires root privileges to execute 'wg set'.
// It does not check if the peer exists before attempting to remove it.
//
// **Returns:**
//
// Returns an error if the peer could not be removed, such as:
//   - Invalid interface name.
//   - Error executing 'wg set'.
//
// **Usage examples:**
//
// ```go
//
//	cfg := set.SinglePeerStructure{
//	    InterfaceName: "wg0",
//	    PublicKey:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
//	}
//
//	err := cfg.RemovePeer()
//	if err != nil {
//	    // Handle the error
//	}
//
// ````
func (p *SinglePeerStructure) RemovePeer() error {
	if p.InterfaceName == "" {
		return fmt.Errorf("error: failed to get Wireguard network interface name")
	}

	if p.PublicKey == "" {
		return fmt.Errorf("error: failed to get public key for peer")
	}

	// Parse PublicKey (mandatory).
	pubKey, err := wgtypes.ParseKey(p.PublicKey)
	if err != nil {
		return fmt.Errorf("error: %v", err)
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: pubKey,
				Remove:    true,
			},
		},
	}

	// Apply configuration.
	newClient, err := handlers.InitWgCtlClient()
	if err != nil {
		return err
	}
	defer newClient.Close()

	err = newClient.ConfigureDevice(p.InterfaceName, config)
	if err != nil {
		return fmt.Errorf(
			"error: failed to update network interface '%s': %v",
			p.InterfaceName, err,
		)
	}

	return nil
}

// Method adds or replaces WireGuard peer configurations.
// This method allows you to add multiple peers to the WireGuard configuration,
// using data from the MultiPeerStructure.
//
// **Parameters:**
//
//   - `replace`: if `true`, existing peer configurations will be replaced,
//     otherwise, new peers will be added to the existing ones. (type: bool)
//
// **Returns:**
//
//   - `nil` if the peer configurations were successfully applied.
//   - An `error` if the configurations cannot be applied (e.g., invalid parameters,
//     WireGuard connection error, data mismatch in the structure fields, wgtypes.configError).
//
// **Features:**
//
//   - The method checks the mandatory fields `InterfaceName`, `PublicKey`, and `AllowedIPs`.
//   - Optional fields `EndpointHost` and `PersistentKeepaliveInterval` can be omitted.
//   - If `EndpointHost` or `PersistentKeepaliveInterval` are not specified for any peer,
//     default values are used (`nil` for `EndpointHost`, `0` for `PersistentKeepaliveInterval`).
//   - The method handles slice length discrepancies by using the minimum length of `AllowedIPs` and `PublicKey`.
//   - The method creates new `wgtypes.PeerConfig` instances for each peer, ensuring configuration isolation.
//   - The method applies peer configurations using the WireGuard client created by the `__init__()` function.
//
// **Usage examples:**
//
// ```go
//
//	cfg := set.MultiPeerStructure{
//	    InterfaceName: "wg0",
//	    PublicKey: []string{
//	        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
//	        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
//	        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
//	    },
//	    EndpointHost: []string{
//	        "192.168.1.56:65535",
//	        "192.168.1.59:64535",
//	    },
//	    AllowedIPs: [][]string{
//	        {"10.10.10.5/32", "10.10.10.9/32"},
//	        {"10.10.10.4/32"},
//	        {"10.10.10.3/32", "10.10.10.10/32"},
//	    },
//	    PersistentKeepaliveInterval: []string{
//	        "10",
//	        "20",
//	        "1",
//	    },
//	}
//
// // Add new peers without replacing existing ones.
//
//	 err := cfg.AddPeer(false)
//	 if err != nil {
//		// Handle error
//	 }
//
// // Replace existing peers with new ones.
//
//	err = cfg.AddPeer(true)
//	if err != nil {
//	    // Handle error
//	}
//
// ```
func (p *MultiPeerStructure) AddPeer(replace bool) error {
	// Check interface name.
	if p.InterfaceName == "" {
		return fmt.Errorf("error: failed to get Wireguard network interface name")
	}

	// Determine loop length.
	lenght := min(len(p.AllowedIPs), len(p.PublicKey))

	// Create slice for peer configurations.
	peerConfig := make([]wgtypes.PeerConfig, 0, lenght)

	// Add peer configurations.
	for i := 0; i < lenght; i++ {
		peer := wgtypes.PeerConfig{}

		// Parse EndpointHost (optional).
		if len(p.EndpointHost) > i && p.EndpointHost[i] != "" {
			endpoint, err := handlers.CheckEndPoint(p.EndpointHost[i])
			if err != nil {
				return err
			}
			peer.Endpoint = endpoint
		}

		// Parse PersistentKeepaliveInterval (optional).
		if len(p.PersistentKeepaliveInterval) > i && p.PersistentKeepaliveInterval[i] != "" {

			num, err := strconv.Atoi(p.PersistentKeepaliveInterval[i])
			if err != nil {
				return fmt.Errorf(
					"error: unable to get KeepAlive interval value %v",
					err,
				)
			}
			if num < 0 {
				num = 0
			}

			duration, err := time.ParseDuration(fmt.Sprintf("%ds", num))
			if err != nil {
				return fmt.Errorf("error: %v", err)
			}
			peer.PersistentKeepaliveInterval = &duration
		} else {
			duration, _ := time.ParseDuration("0s")
			peer.PersistentKeepaliveInterval = &duration
		}

		// Parse PublicKey (mandatory).
		pubKey, err := wgtypes.ParseKey(p.PublicKey[i])
		if err != nil {
			return fmt.Errorf("error: %v", err)
		}
		peer.PublicKey = pubKey

		// Parse AllowedIPs (mandatory).
		alwIps, err := handlers.CheckAllowedIPs(p.AllowedIPs[i])
		if err != nil {
			return err
		}
		peer.AllowedIPs = alwIps

		// Add peer configuration to slice.
		peerConfig = append(peerConfig, peer)
	}

	// Apply configuration.
	newClient, err := handlers.InitWgCtlClient()
	if err != nil {
		return err
	}
	defer newClient.Close()

	config := wgtypes.Config{
		ReplacePeers: replace,
		Peers:        peerConfig,
	}
	err = newClient.ConfigureDevice(p.InterfaceName, config)
	if err != nil {
		return fmt.Errorf(
			"error: failed to update network interface '%s': %v",
			p.InterfaceName,
			err,
		)
	}

	return nil
}

// Method removes multiple WireGuard peers from the configuration.
//
// **Returns:**
// Returns an error if the peers could not be removed.
//
// **Usage examples:**
//
// ```go
//
//	cfg := set.MultiPeerStructure{
//		InterfaceName: "wg0",
//		PublicKey: []string{
//			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
//			"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
//		},
//	}
//
// err := cfg.RemovePeer()
//
//	if err != nil {
//		// Handle error
//	}
//
// ```
func (p *MultiPeerStructure) RemovePeer() error {
	// Check interface name.
	if p.InterfaceName == "" {
		return fmt.Errorf("error: failed to get Wireguard network interface name")
	}

	lenght := len(p.PublicKey)
	if lenght == 0 {
		return fmt.Errorf("error: failed to get public key for peer")
	}

	// Create slice for peer configurations.
	peerConfig := make([]wgtypes.PeerConfig, 0, lenght)

	for i := 0; i < lenght; i++ {
		// Parse PublicKey (mandatory).
		pubKey, err := wgtypes.ParseKey(p.PublicKey[i])
		if err != nil {
			return fmt.Errorf("error: failed to get keys: %v", err)
		}

		peer := wgtypes.PeerConfig{
			Remove:    true,
			PublicKey: pubKey,
		}
		// Add peer configuration to slice.
		peerConfig = append(peerConfig, peer)
	}

	// Apply configuration.
	newClient, err := handlers.InitWgCtlClient()
	if err != nil {
		return err
	}
	defer newClient.Close()

	config := wgtypes.Config{Peers: peerConfig}
	err = newClient.ConfigureDevice(p.InterfaceName, config)
	if err != nil {
		return fmt.Errorf(
			"error: failed to update network interface '%s': %v",
			p.InterfaceName, err,
		)
	}

	return nil
}
