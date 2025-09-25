package subnet

import (
	"fmt"
	"net"
	"strings"

	utilnet "k8s.io/utils/net"
)

// RangeConstraint represents an IP range constraint for allocation
type RangeConstraint struct {
	// StartIP is the first IP in the range (nil for CIDR-only ranges)
	StartIP net.IP
	// EndIP is the last IP in the range (nil for CIDR-only ranges)
	EndIP net.IP
	// Subnet is the encompassing subnet for this range
	Subnet *net.IPNet
	// OriginalSpec is the original string specification (for debugging)
	OriginalSpec string
	// Type indicates the range type
	Type RangeType
}

// RangeType indicates how the range was specified
type RangeType int

const (
	RangeTypeCIDR RangeType = iota
	RangeTypeHyphenated
	RangeTypeSingleIP
)

// Contains checks if an IP is within the range constraint
func (rc *RangeConstraint) Contains(ip net.IP) bool {
	// For CIDR ranges, just check subnet membership
	if rc.Type == RangeTypeCIDR {
		return rc.Subnet.Contains(ip)
	}

	// For hyphenated and single IP ranges, check the specific bounds
	if rc.StartIP == nil || rc.EndIP == nil {
		return rc.Subnet.Contains(ip)
	}

	// Convert to comparable format
	if ip.To4() != nil {
		// IPv4 comparison
		startBytes := rc.StartIP.To4()
		endBytes := rc.EndIP.To4()
		ipBytes := ip.To4()

		if startBytes == nil || endBytes == nil || ipBytes == nil {
			return false
		}

		start := bytesToUint32(startBytes)
		end := bytesToUint32(endBytes)
		ipVal := bytesToUint32(ipBytes)

		return ipVal >= start && ipVal <= end
	} else {
		// IPv6 comparison - simplified for same /64 subnet
		startBytes := rc.StartIP.To16()
		endBytes := rc.EndIP.To16()
		ipBytes := ip.To16()

		if startBytes == nil || endBytes == nil || ipBytes == nil {
			return false
		}

		// Check if in same /64 prefix
		for i := 0; i < 8; i++ {
			if startBytes[i] != ipBytes[i] || endBytes[i] != ipBytes[i] {
				return false
			}
		}

		start := bytesToUint64(startBytes[8:])
		end := bytesToUint64(endBytes[8:])
		ipVal := bytesToUint64(ipBytes[8:])

		return ipVal >= start && ipVal <= end
	}
}

// String returns a human-readable representation of the range constraint
func (rc *RangeConstraint) String() string {
	switch rc.Type {
	case RangeTypeCIDR:
		return rc.Subnet.String()
	case RangeTypeHyphenated:
		return fmt.Sprintf("%s-%s (subnet: %s)", rc.StartIP, rc.EndIP, rc.Subnet)
	case RangeTypeSingleIP:
		return fmt.Sprintf("%s (subnet: %s)", rc.StartIP, rc.Subnet)
	default:
		return rc.OriginalSpec
	}
}

// ParseIPRangesWithConstraints parses various IP range formats and returns both subnets and range constraints
func ParseIPRangesWithConstraints(strs []string) ([]*net.IPNet, []*RangeConstraint, error) {
	var subnets []*net.IPNet
	var constraints []*RangeConstraint

	for _, str := range strs {
		constraint, err := parseIPRangeWithConstraint(str)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse IP range %q: %w", str, err)
		}
		subnets = append(subnets, constraint.Subnet)
		constraints = append(constraints, constraint)
	}
	return subnets, constraints, nil
}

// ParseIPRanges parses various IP range formats including:
// - CIDR notation: 192.168.10.0/24, fc00:f853:0ccd:e799::/124
// - Hyphenated range: 192.168.20.1-192.168.20.50
// - Single IP via CIDR: 192.168.30.100/32
// Deprecated: Use ParseIPRangesWithConstraints for range-aware allocation
func ParseIPRanges(strs []string) ([]*net.IPNet, error) {
	subnets, _, err := ParseIPRangesWithConstraints(strs)
	return subnets, err
}

// parseIPRangeWithConstraint parses a single IP range string and returns a RangeConstraint
func parseIPRangeWithConstraint(str string) (*RangeConstraint, error) {
	originalStr := str
	str = strings.TrimSpace(str)

	// Check if it's a hyphenated range
	if strings.Contains(str, "-") {
		return parseHyphenatedRangeWithConstraint(originalStr)
	}

	// Try parsing as CIDR (including single IP with /32 or /128)
	ip, ipnet, err := utilnet.ParseCIDRSloppy(str)
	if err != nil {
		return nil, err
	}
	ipnet.IP = ip

	// Determine if this is a single IP or a CIDR range
	ones, bits := ipnet.Mask.Size()
	rangeType := RangeTypeCIDR
	if (bits == 32 && ones == 32) || (bits == 128 && ones == 128) {
		rangeType = RangeTypeSingleIP
	}

	return &RangeConstraint{
		StartIP:      ip,
		EndIP:        ip,
		Subnet:       ipnet,
		OriginalSpec: originalStr,
		Type:         rangeType,
	}, nil
}

// parseIPRange parses a single IP range string and returns multiple IPNets for hyphenated ranges
// Deprecated: Use parseIPRangeWithConstraint for range-aware allocation
func parseIPRange(str string) ([]*net.IPNet, error) {
	constraint, err := parseIPRangeWithConstraint(str)
	if err != nil {
		return nil, err
	}
	return []*net.IPNet{constraint.Subnet}, nil
}

// parseHyphenatedRangeWithConstraint parses ranges like "192.168.20.1-192.168.20.50" with constraints
func parseHyphenatedRangeWithConstraint(str string) (*RangeConstraint, error) {
	parts := strings.Split(str, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid hyphenated range format: %s", str)
	}

	startIPStr := strings.TrimSpace(parts[0])
	endIPStr := strings.TrimSpace(parts[1])

	startIP := net.ParseIP(startIPStr)
	if startIP == nil {
		return nil, fmt.Errorf("invalid start IP: %s", startIPStr)
	}

	endIP := net.ParseIP(endIPStr)
	if endIP == nil {
		return nil, fmt.Errorf("invalid end IP: %s", endIPStr)
	}

	// Ensure both IPs are the same version (IPv4 or IPv6)
	if (startIP.To4() == nil) != (endIP.To4() == nil) {
		return nil, fmt.Errorf("start and end IPs must be the same version: %s-%s", startIPStr, endIPStr)
	}

	// Create encompassing subnet
	var subnet *net.IPNet
	var err error

	if startIP.To4() != nil {
		// IPv4
		startBytes := startIP.To4()
		endBytes := endIP.To4()

		start := bytesToUint32(startBytes)
		end := bytesToUint32(endBytes)

		if start > end {
			return nil, fmt.Errorf("start IP %s is greater than end IP %s", startIPStr, endIPStr)
		}

		subnet, err = createEncompassingSubnet(startIP, endIP)
		if err != nil {
			return nil, err
		}
	} else {
		// IPv6 - for simplicity, we'll only support ranges within the same /64 subnet
		startBytes := startIP.To16()
		endBytes := endIP.To16()

		// Check if they're in the same /64 subnet
		for i := 0; i < 8; i++ {
			if startBytes[i] != endBytes[i] {
				return nil, fmt.Errorf("IPv6 hyphenated ranges are only supported within the same /64 subnet")
			}
		}

		start := bytesToUint64(startBytes[8:])
		end := bytesToUint64(endBytes[8:])

		if start > end {
			return nil, fmt.Errorf("start IP %s is greater than end IP %s", startIPStr, endIPStr)
		}

		// Create a /64 subnet for the IPv6 range
		prefix := make(net.IP, 16)
		copy(prefix[:8], startBytes[:8])
		copy(prefix[8:], []byte{0, 0, 0, 0, 0, 0, 0, 0})

		subnet = &net.IPNet{
			IP:   prefix,
			Mask: net.CIDRMask(64, 128),
		}
	}

	return &RangeConstraint{
		StartIP:      startIP,
		EndIP:        endIP,
		Subnet:       subnet,
		OriginalSpec: str,
		Type:         RangeTypeHyphenated,
	}, nil
}

// parseHyphenatedRange parses ranges like "192.168.20.1-192.168.20.50"
// Deprecated: Use parseHyphenatedRangeWithConstraint for range-aware allocation
func parseHyphenatedRange(str string) ([]*net.IPNet, error) {
	parts := strings.Split(str, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid hyphenated range format: %s", str)
	}

	startIPStr := strings.TrimSpace(parts[0])
	endIPStr := strings.TrimSpace(parts[1])

	startIP := net.ParseIP(startIPStr)
	if startIP == nil {
		return nil, fmt.Errorf("invalid start IP: %s", startIPStr)
	}

	endIP := net.ParseIP(endIPStr)
	if endIP == nil {
		return nil, fmt.Errorf("invalid end IP: %s", endIPStr)
	}

	// Ensure both IPs are the same version (IPv4 or IPv6)
	if (startIP.To4() == nil) != (endIP.To4() == nil) {
		return nil, fmt.Errorf("start and end IPs must be the same version: %s-%s", startIPStr, endIPStr)
	}

	// Create a encompassing subnet for the hyphenated range
	// We'll create a subnet that covers the range and let the allocator handle individual allocations
	if startIP.To4() != nil {
		// IPv4
		startBytes := startIP.To4()
		endBytes := endIP.To4()

		start := bytesToUint32(startBytes)
		end := bytesToUint32(endBytes)

		if start > end {
			return nil, fmt.Errorf("start IP %s is greater than end IP %s", startIPStr, endIPStr)
		}

		// Calculate the minimum subnet that encompasses this range
		subnet, err := createEncompassingSubnet(startIP, endIP)
		if err != nil {
			return nil, err
		}

		return []*net.IPNet{subnet}, nil
	} else {
		// IPv6 - for simplicity, we'll only support ranges within the same /64 subnet
		startBytes := startIP.To16()
		endBytes := endIP.To16()

		// Check if they're in the same /64 subnet
		for i := 0; i < 8; i++ {
			if startBytes[i] != endBytes[i] {
				return nil, fmt.Errorf("IPv6 hyphenated ranges are only supported within the same /64 subnet")
			}
		}

		start := bytesToUint64(startBytes[8:])
		end := bytesToUint64(endBytes[8:])

		if start > end {
			return nil, fmt.Errorf("start IP %s is greater than end IP %s", startIPStr, endIPStr)
		}

		// Create a /64 subnet for the IPv6 range
		prefix := make(net.IP, 16)
		copy(prefix[:8], startBytes[:8])
		copy(prefix[8:], []byte{0, 0, 0, 0, 0, 0, 0, 0})

		subnet := &net.IPNet{
			IP:   prefix,
			Mask: net.CIDRMask(64, 128),
		}

		return []*net.IPNet{subnet}, nil
	}
}

// createEncompassingSubnet creates the smallest subnet that encompasses the range from startIP to endIP
func createEncompassingSubnet(startIP, endIP net.IP) (*net.IPNet, error) {
	if startIP.To4() == nil {
		return nil, fmt.Errorf("IPv6 not supported in createEncompassingSubnet")
	}

	start := bytesToUint32(startIP.To4())
	end := bytesToUint32(endIP.To4())

	// Find the common prefix bits
	xor := start ^ end
	if xor == 0 {
		// Same IP, return /32
		return &net.IPNet{IP: startIP, Mask: net.CIDRMask(32, 32)}, nil
	}

	// Count leading zeros in XOR to find common prefix length
	prefixLen := 32
	for i := uint32(31); i >= 0; i-- {
		if (xor & (1 << i)) != 0 {
			prefixLen = int(32 - i - 1)
			break
		}
	}

	// Create network address by masking start IP
	mask := net.CIDRMask(prefixLen, 32)
	networkAddr := make(net.IP, 4)
	startBytes := startIP.To4()
	for i := 0; i < 4; i++ {
		networkAddr[i] = startBytes[i] & mask[i]
	}

	return &net.IPNet{
		IP:   networkAddr,
		Mask: mask,
	}, nil
}

// Helper functions for byte/uint conversions
func bytesToUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32ToBytes(u uint32) net.IP {
	return net.IPv4(byte(u>>24), byte(u>>16), byte(u>>8), byte(u))
}

func bytesToUint64(b []byte) uint64 {
	var result uint64
	for i := 0; i < 8; i++ {
		result = result<<8 | uint64(b[i])
	}
	return result
}

func uint64ToBytes(u uint64) []byte {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(u)
		u >>= 8
	}
	return b
}

// ParseIPNets parses the provided string formatted CIDRs
// Deprecated: Use ParseIPRanges for more flexible range support
func ParseIPNets(strs []string) ([]*net.IPNet, error) {
	ipnets := make([]*net.IPNet, len(strs))
	for i := range strs {
		ip, ipnet, err := utilnet.ParseCIDRSloppy(strs[i])
		if err != nil {
			return nil, err
		}
		ipnet.IP = ip
		ipnets[i] = ipnet
	}
	return ipnets, nil
}

// MustParseIP is like net.ParseIP but it panics on error; use this for converting
// compile-time constant strings to net.IP
func MustParseIP(ipStr string) net.IP {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		panic(fmt.Sprintf("Could not parse %q as an IP address", ipStr))
	}
	return ip
}

// MustParseIPs is like MustParseIP but returns an array of net.IP
func MustParseIPs(ipStrs ...string) []net.IP {
	ips := make([]net.IP, len(ipStrs))
	for i := range ipStrs {
		ips[i] = MustParseIP(ipStrs[i])
	}
	return ips
}

// MustParseIPNet is like netlink.ParseIPNet or net.ParseCIDR, except that it panics on
// error; use this for converting compile-time constant strings to net.IPNet.
func MustParseIPNet(cidrStr string) *net.IPNet {
	ip, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		panic(fmt.Sprintf("Could not parse %q as a CIDR: %v", cidrStr, err))
	}
	// To make this compatible both with code that does
	//
	//     _, ipNet, err := net.ParseCIDR(str)
	//
	// and code that does
	//
	//    ipNet, err := netlink.ParseIPNet(str)
	//    ipNet.IP = ip
	//
	// we replace ipNet.IP with ip only if they aren't already equal. This sounds like
	// a no-op but it isn't; in particular, when parsing an IPv4 CIDR, net.ParseCIDR()
	// returns a 4-byte ip but a 16-byte ipNet.IP, so if we just unconditionally
	// replace the latter with the former, it will no longer compare as byte-for-byte
	// equal to the original value.
	if !ipNet.IP.Equal(ip) {
		ipNet.IP = ip
	}
	return ipNet
}

// MustParseIPNets is like MustParseIPNet but returns an array of *net.IPNet
func MustParseIPNets(ipNetStrs ...string) []*net.IPNet {
	ipNets := make([]*net.IPNet, len(ipNetStrs))
	for i := range ipNetStrs {
		ipNets[i] = MustParseIPNet(ipNetStrs[i])
	}
	return ipNets
}

// SubnetBroadcastIP returns the IP network's broadcast IP.
func SubnetBroadcastIP(ipnet net.IPNet) net.IP {
	ip := ipnet.IP
	mask := ipnet.Mask

	// Handle IPv4 addresses in 16-byte representation
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	result := make(net.IP, len(ip))

	// broadcastIP = (networkIP) | (inverted mask)
	for i := range ip {
		result[i] = (ip[i] & mask[i]) | (mask[i] ^ 0xff)
	}
	return result
}

// ContainsCIDR returns true if ipnet1 contains ipnet2
func ContainsCIDR(ipnet1, ipnet2 *net.IPNet) bool {
	mask1, _ := ipnet1.Mask.Size()
	mask2, _ := ipnet2.Mask.Size()
	return mask1 <= mask2 && ipnet1.Contains(ipnet2.IP)
}
