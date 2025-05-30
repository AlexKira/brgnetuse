// Package contains the structures needed to control the set utility.
package set

// UpdatePrivateKeyStructure represents the data needed to update the private key
// of a WireGuard interface.
type UpdatePrivateKeyStructure struct {
	// WireGuard network interface name.
	//
	// InterfaceName is a mandatory field.
	InterfaceName string

	// PrivateKey specifies the private key of this WireGuard peer (base64 encoded).
	PrivateKey string
}

// SinglePeerStructure represents the configuration of a single WireGuard peer.
type SinglePeerStructure struct {
	// WireGuard network interface name.
	//
	// InterfaceName is a mandatory field.
	InterfaceName string

	// PublicKey specifies the public key of this WireGuard peer (base64 encoded).
	//
	// PublicKey is a mandatory field.
	PublicKey string

	// AllowedIPs specifies a list of allowed IP addresses (as strings) in CIDR
	// notation for this peer.
	//
	// AllowedIPs is a mandatory field.
	AllowedIPs []string

	// Endpoint specifies the endpoint of this peer entry. If empty, no endpoint is set.
	//
	//// Example: 89.89.89.1:51820
	EndpointHost string

	// PersistentKeepaliveInterval for checking if a peer is alive, measured in seconds.
	// A non-zero value of 0 will clear the persistent keepalive interval.
	PersistentKeepaliveInterval string
}

// MultiPeerStructure represents a configuration of multiple WireGuard peers.
type MultiPeerStructure struct {
	// WireGuard network interface name.
	//
	// InterfaceName is a mandatory field.
	InterfaceName string

	// PublicKey specifies a list of public keys (base64 encoded) for each WireGuard peer.
	//Example: []string{"AAAAAAAAAAAAAAAAAAAAAAA=", "BBBBBBBBBBBB="}
	//
	// PublicKey is a mandatory field.
	PublicKey []string

	// AllowedIPs specifies a list of allowed IP address lists (in CIDR notation)
	// for each WireGuard peer.
	//Example: [][]string{{"10.10.10.3/32", "10.10.10.10/32"},{"10.10.10.4/32"}}
	//
	// AllowedIPs is a mandatory field.
	AllowedIPs [][]string

	// EndpointHost specifies a list of endpoints for each WireGuard peer entry.
	// If an entry is empty, no endpoint is set for that peer.
	//Example: []string{"89.89.89.1:51820", "172.172.89.1:50820"}
	//
	// EndpointHost is an optional field.
	EndpointHost []string

	// PersistentKeepaliveInterval specifies a list of keepalive intervals
	// for each WireGuard peer to check for peer activity, measured in seconds.
	// A non-zero value of 0 will clear the persistent keepalive interval for that peer.
	//
	// PersistentKeepaliveInterval is an optional field.
	PersistentKeepaliveInterval []string
}
