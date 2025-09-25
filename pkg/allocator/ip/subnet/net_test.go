package subnet

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseIPRanges(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string // Expected IP addresses or CIDR blocks
		wantErr  bool
	}{
		{
			name:     "CIDR notation IPv4",
			input:    []string{"192.168.10.0/24"},
			expected: []string{"192.168.10.0/24"},
			wantErr:  false,
		},
		{
			name:     "CIDR notation IPv6",
			input:    []string{"fc00:f853:0ccd:e799::/124"},
			expected: []string{"fc00:f853:ccd:e799::/124"},
			wantErr:  false,
		},
		{
			name:     "Single IP via CIDR IPv4",
			input:    []string{"192.168.30.100/32"},
			expected: []string{"192.168.30.100/32"},
			wantErr:  false,
		},
		{
			name:     "Single IP via CIDR IPv6",
			input:    []string{"fc00:f853:0ccd:e799::100/128"},
			expected: []string{"fc00:f853:ccd:e799::100/128"},
			wantErr:  false,
		},
		{
			name:     "Hyphenated range IPv4 small",
			input:    []string{"192.168.20.1-192.168.20.3"},
			expected: []string{"192.168.20.0/30"}, // Encompasses .1-.3 range
			wantErr:  false,
		},
		{
			name:     "Hyphenated range IPv6 small",
			input:    []string{"fc00:f853:0ccd:e799::1-fc00:f853:0ccd:e799::3"},
			expected: []string{"fc00:f853:ccd:e799::/64"}, // IPv6 ranges create /64 subnets
			wantErr:  false,
		},
		{
			name:     "Mixed formats",
			input:    []string{"192.168.10.0/24", "192.168.20.1-192.168.20.2", "192.168.30.100/32"},
			expected: []string{"192.168.10.0/24", "192.168.20.0/30", "192.168.30.100/32"}, // Range .1-.2 becomes /30
			wantErr:  false,
		},
		{
			name:    "Invalid CIDR",
			input:   []string{"192.168.10.0/35"},
			wantErr: true,
		},
		{
			name:    "Invalid hyphenated range - mixed IP versions",
			input:   []string{"192.168.1.1-fc00::1"},
			wantErr: true,
		},
		{
			name:    "Invalid hyphenated range - start > end",
			input:   []string{"192.168.1.10-192.168.1.5"},
			wantErr: true,
		},
		{
			name:    "Invalid hyphenated range - different IPv6 prefixes",
			input:   []string{"fc00:f853:0ccd:e799::1-fc00:f853:0ccd:e800::1"},
			wantErr: true,
		},
		{
			name:    "Invalid hyphenated range - too many parts",
			input:   []string{"192.168.1.1-192.168.1.5-192.168.1.10"},
			wantErr: true,
		},
		{
			name:    "Invalid IP in range",
			input:   []string{"192.168.1.300-192.168.1.301"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseIPRanges(tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Len(t, result, len(tt.expected))

			for i, expected := range tt.expected {
				assert.Equal(t, expected, result[i].String())
			}
		})
	}
}

func TestParseHyphenatedRange(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
		wantErr  bool
	}{
		{
			name:     "IPv4 range single IP",
			input:    "192.168.1.10-192.168.1.10",
			expected: []string{"192.168.1.10/32"},
			wantErr:  false,
		},
		{
			name:     "IPv4 range multiple IPs",
			input:    "10.0.0.1-10.0.0.5",
			expected: []string{"10.0.0.0/29"}, // Encompasses .1-.5 range
			wantErr:  false,
		},
		{
			name:     "IPv6 range single IP",
			input:    "2001:db8::1-2001:db8::1",
			expected: []string{"2001:db8::/64"}, // IPv6 ranges create /64 subnets
			wantErr:  false,
		},
		{
			name:     "IPv6 range multiple IPs",
			input:    "2001:db8::1-2001:db8::3",
			expected: []string{"2001:db8::/64"}, // IPv6 ranges create /64 subnets
			wantErr:  false,
		},
		{
			name:    "Mixed IP versions",
			input:   "192.168.1.1-2001:db8::1",
			wantErr: true,
		},
		{
			name:    "Invalid start IP",
			input:   "invalid-192.168.1.10",
			wantErr: true,
		},
		{
			name:    "Invalid end IP",
			input:   "192.168.1.10-invalid",
			wantErr: true,
		},
		{
			name:    "Start greater than end",
			input:   "192.168.1.10-192.168.1.5",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseHyphenatedRange(tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Len(t, result, len(tt.expected))

			for i, expected := range tt.expected {
				assert.Equal(t, expected, result[i].String())
			}
		})
	}
}

func TestByteConversions(t *testing.T) {
	t.Run("uint32 conversions", func(t *testing.T) {
		ip := net.IPv4(192, 168, 1, 10)
		bytes := ip.To4()
		uint32Val := bytesToUint32(bytes)
		convertedIP := uint32ToBytes(uint32Val)
		assert.True(t, ip.Equal(convertedIP))
	})

	t.Run("uint64 conversions", func(t *testing.T) {
		testBytes := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01}
		uint64Val := bytesToUint64(testBytes)
		convertedBytes := uint64ToBytes(uint64Val)
		assert.Equal(t, testBytes, convertedBytes)
	})
}

func TestParseIPRange(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
		wantErr  bool
	}{
		{
			name:     "CIDR format",
			input:    "192.168.1.0/24",
			expected: []string{"192.168.1.0/24"},
			wantErr:  false,
		},
		{
			name:     "Single IP as CIDR",
			input:    "192.168.1.10/32",
			expected: []string{"192.168.1.10/32"},
			wantErr:  false,
		},
		{
			name:     "Hyphenated range",
			input:    "192.168.1.1-192.168.1.2",
			expected: []string{"192.168.1.0/30"}, // Encompasses .1-.2 range
			wantErr:  false,
		},
		{
			name:    "Invalid format",
			input:   "invalid.ip.format",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseIPRange(tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Len(t, result, len(tt.expected))

			for i, expected := range tt.expected {
				assert.Equal(t, expected, result[i].String())
			}
		})
	}
}

// Integration test with real-world MetalLB-style examples
func TestMetalLBStyleRanges(t *testing.T) {
	input := []string{
		"192.168.10.0/24",        // CIDR notation
		"192.168.20.1-192.168.20.50", // Hyphenated range
		"192.168.30.100/32",      // Single IP via CIDR
		"fc00:f853:ccd:e799::/124", // IPv6 CIDR
	}

	result, err := ParseIPRanges(input)
	require.NoError(t, err)

	// Should have: 1 IPv4 /24 + 1 IPv4 range subnet + 1 IPv4 /32 + 1 IPv6 /124 = 4 total
	expectedCount := 4 // 1 + 1 + 1 + 1
	assert.Len(t, result, expectedCount)

	// Check some specific results
	assert.Equal(t, "192.168.10.0/24", result[0].String())
	// The hyphenated range 192.168.20.1-192.168.20.50 will create an encompassing subnet
	// This covers .0-.63, so it will be /26
	assert.Contains(t, result[1].String(), "192.168.20.")
	assert.Equal(t, "192.168.30.100/32", result[2].String())
	assert.Equal(t, "fc00:f853:ccd:e799::/124", result[3].String())
}

// Test range-aware parsing with constraints
func TestParseIPRangesWithConstraints(t *testing.T) {
	input := []string{
		"192.168.10.0/24",        // CIDR notation
		"192.168.20.1-192.168.20.5", // Hyphenated range
		"192.168.30.100/32",      // Single IP via CIDR
	}

	subnets, constraints, err := ParseIPRangesWithConstraints(input)
	require.NoError(t, err)
	assert.Len(t, subnets, 3)
	assert.Len(t, constraints, 3)

	// Check constraint types
	assert.Equal(t, RangeTypeCIDR, constraints[0].Type)
	assert.Equal(t, RangeTypeHyphenated, constraints[1].Type)
	assert.Equal(t, RangeTypeSingleIP, constraints[2].Type)

	// Check constraint boundaries
	assert.Equal(t, "192.168.10.0", constraints[0].StartIP.String())
	assert.Equal(t, "192.168.20.1", constraints[1].StartIP.String())
	assert.Equal(t, "192.168.20.5", constraints[1].EndIP.String())
	assert.Equal(t, "192.168.30.100", constraints[2].StartIP.String())

	// Test Contains method
	assert.True(t, constraints[0].Contains(net.ParseIP("192.168.10.50")))
	assert.False(t, constraints[0].Contains(net.ParseIP("192.168.11.1")))

	assert.True(t, constraints[1].Contains(net.ParseIP("192.168.20.3")))
	assert.False(t, constraints[1].Contains(net.ParseIP("192.168.20.10")))

	assert.True(t, constraints[2].Contains(net.ParseIP("192.168.30.100")))
	assert.False(t, constraints[2].Contains(net.ParseIP("192.168.30.101")))
}

func TestRangeConstraintContains(t *testing.T) {
	tests := []struct {
		name       string
		constraint *RangeConstraint
		testIP     string
		expected   bool
	}{
		{
			name: "CIDR range contains IP",
			constraint: &RangeConstraint{
				Type:   RangeTypeCIDR,
				Subnet: mustParseCIDR("192.168.1.0/24"),
			},
			testIP:   "192.168.1.100",
			expected: true,
		},
		{
			name: "CIDR range excludes IP",
			constraint: &RangeConstraint{
				Type:   RangeTypeCIDR,
				Subnet: mustParseCIDR("192.168.1.0/24"),
			},
			testIP:   "192.168.2.100",
			expected: false,
		},
		{
			name: "Hyphenated range contains IP",
			constraint: &RangeConstraint{
				Type:    RangeTypeHyphenated,
				StartIP: net.ParseIP("192.168.1.10"),
				EndIP:   net.ParseIP("192.168.1.20"),
				Subnet:  mustParseCIDR("192.168.1.0/28"),
			},
			testIP:   "192.168.1.15",
			expected: true,
		},
		{
			name: "Hyphenated range excludes IP below range",
			constraint: &RangeConstraint{
				Type:    RangeTypeHyphenated,
				StartIP: net.ParseIP("192.168.1.10"),
				EndIP:   net.ParseIP("192.168.1.20"),
				Subnet:  mustParseCIDR("192.168.1.0/28"),
			},
			testIP:   "192.168.1.5",
			expected: false,
		},
		{
			name: "Hyphenated range excludes IP above range",
			constraint: &RangeConstraint{
				Type:    RangeTypeHyphenated,
				StartIP: net.ParseIP("192.168.1.10"),
				EndIP:   net.ParseIP("192.168.1.20"),
				Subnet:  mustParseCIDR("192.168.1.0/28"),
			},
			testIP:   "192.168.1.25",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.constraint.Contains(net.ParseIP(tt.testIP))
			assert.Equal(t, tt.expected, result)
		})
	}
}

func mustParseCIDR(cidr string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return ipnet
}