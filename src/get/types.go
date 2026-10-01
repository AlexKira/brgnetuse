// Package contains the structures needed to control the get utility.

package get

// AddrInfoStructure represents information about an IP address.
type AddrInfoStructure struct {
	Family string `json:"family"`
	Local  string `json:"local"`

	Prefixlen         int    `json:"prefixlen"`
	Scope             string `json:"scope"`
	Dynamic           bool   `json:"dynamic"`
	Label             string `json:"label"`
	ValidLifeTime     int    `json:"valid_life_time"`
	PreferredLifeTime int    `json:"preferred_life_time"`
}

// IpInterfaceStructure represents information about a network interface.
type IpInterfaceStructure struct {
	IfIndex   int                 `json:"ifindex"`
	IfName    string              `json:"ifname"`
	Flags     []string            `json:"flags"`
	MTU       int                 `json:"mtu"`
	Qdisc     string              `json:"qdisc"`
	OperState string              `json:"operstate"`
	Group     string              `json:"group"`
	TxQLen    int                 `json:"txqlen"`
	LinkType  string              `json:"link_type"`
	Address   string              `json:"address"`
	Broadcast string              `json:"broadcast"`
	AddrInfo  []AddrInfoStructure `json:"addr_info"`
}

// IptablesRule represents a single rule within an iptables chain.
//
// It encapsulates the various fields associated with an iptables rule,
// such as packet and byte counts, target action, protocol, options,
// input and output interfaces, and source/destination addresses.
type IptablesRule struct {
	// Identifier field in table rules.
	Id uint64

	// Pkts represents the number of packets that have matched this rule.
	Pkts int

	// Bytes represents the total size (in bytes) of packets that have
	// matched this rule.
	Bytes int

	// Target specifies the action to take when a packet matches
	// this rule (e.g., ACCEPT, DROP, REJECT).
	Target string

	// Prot specifies the protocol that this rule applies to
	// (e.g., tcp, udp, icmp).
	Prot string

	// Opt specifies any additional options for the rule.
	Opt string

	// In specifies the input interface that this rule applies to.
	In string

	// Out specifies the output interface that this rule applies to.
	Out string

	// Source specifies the source address or network that this rule
	// applies to.
	Source string

	// Destination specifies the destination address or network that
	// this rule applies to.
	Destination string

	// Options specifies any additional match extensions or parameters for the rule,
	// such as connection state (e.g., "ctstate RELATED,ESTABLISHED")
	// or specific protocol options (e.g., "tcp dpt:22").
	Options string
}

// IptablesChain represents an iptables chain, which is a collection of rules.
//
// It encapsulates the chain's name, policy, packet and byte counts, and
// a slice of IptablesRule structures representing the rules within the chain.
type IptablesChain struct {
	// Name specifies the name of the iptables chain
	// (e.g., INPUT, FORWARD, OUTPUT).
	Name string

	// Policy specifies the default action to take when a packet
	// does not match any rule in the chain.
	Policy string

	// Packets represents the number of packets that have entered
	// this chain.
	Packets int

	// Bytes represents the total size (in bytes) of packets
	// that have entered this chain.
	Bytes int

	// References specifies the number of references to this chain.
	// This field is populated for custom chains (e.g., DOCKER (2 references)).
	References int

	// Rules is a slice of IptablesRule structures representing
	// the rules within this chain.
	Rules []IptablesRule
}

// IptablesOutput represents the complete output of an iptables command,
// containing a collection of iptables chains.
//
// It encapsulates a slice of IptablesChain structures, where each element
// represents a different chain defined within the iptables firewall.
type IptablesOutput struct {
	// Chains is a slice of IptablesChain structures, representing the
	// different chains defined within the iptables firewall.
	Chains []IptablesChain
}

// AwgObfuscateStructure defines the AmneziaWG protocol obfuscation configuration for production deployments.
type AwgObfuscateStructure struct {
	Jc   uint16 `json:"jc"`   // Number of junk packets. Example: 4.
	Jmin uint16 `json:"jmin"` // Minimum junk packet size. Example: 80.
	Jmax uint16 `json:"jmax"` // Maximum junk packet size. Example: 160.

	S1 uint16 `json:"s1"` // Random prefix for Init packets. Example: 12.
	S2 uint16 `json:"s2"` // Random prefix for Response packets. Example: 13.
	S3 uint16 `json:"s3"` // Random prefix for Cookie packets. Example: 14.
	S4 uint16 `json:"s4"` // Random prefix for Data packets. Example: 15.

	H1 string `json:"h1"` // Custom message type identifier or uint32 range. Example: "150000000-200000000".
	H2 string `json:"h2"` // Custom message type identifier or uint32 range. Example: "250000000-300000000".
	H3 string `json:"h3"` // Custom message type identifier or uint32 range. Example: "350000000-400000000".
	H4 string `json:"h4"` // Custom message type identifier or uint32 range. Example: "450000000-500000000".

	I1 string `json:"i1"` // CPS-description for the first camouflage packet. Example: "<r 20>".
	I2 string `json:"i2"` // CPS-description for the second camouflage packet. Example: "<r 15>".
	I3 string `json:"i3"` // CPS-description for the third camouflage packet. Example: "<r 12>".
	I4 string `json:"i4"` // CPS-description for the fourth camouflage packet. Example: "<r 18>".
	I5 string `json:"i5"` // CPS-description for the fifth camouflage packet. Example: "<r 14>".

	HeaderProtectionKey string `json:"header_protection_key"` // 32-byte key for Header Protection. Example: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".

	ContentPaddingAddition string `json:"content_padding_addition"` // Random transport payload padding range. Example: "10-100".
	RekeyAfterTime         string `json:"rekey_after_time"`         // Time interval before rekey. Example: "10-20".
	RekeyTimeout           string `json:"rekey_timeout"`            // Handshake timeout range. Example: "15-30".
	RejectAfterTime        string `json:"reject_after_time"`        // Time interval after which a new handshake is initiated when no data is received. Example: "20-40".
	KeepaliveTimeout       string `json:"keepalive_timeout"`        // Interval before sending keepalive. Example: "25-50".
	MaxHandshakeAttempts   string `json:"max_handshake_attempts"`   // Maximum number of handshake attempts. Example: "2-3".

	RandomTrailers bool `json:"random_trailers"` // Add random packet trailers. Example: true.
	DisableCookies bool `json:"disable_cookies"` // Disable Cookie Reply packets. Example: true.
}
