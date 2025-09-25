package subnet

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRangeAwareAllocator(t *testing.T) {
	allocator := NewAllocator()

	t.Run("Hyphenated range allocation stays within bounds", func(t *testing.T) {
		// Test hyphenated range: 192.168.1.10-192.168.1.15
		addresses := []string{"192.168.1.10-192.168.1.15"}
		subnets, constraints, err := ParseIPRangesWithConstraints(addresses)
		require.NoError(t, err)

		config := SubnetConfig{
			Name:             "test-hyphenated",
			Subnets:          subnets,
			RangeConstraints: constraints,
		}

		err = allocator.AddOrUpdateSubnet(config)
		require.NoError(t, err)

		// Allocate multiple IPs and verify they're all within the original range
		for i := 0; i < 5; i++ {
			ips, err := allocator.AllocateNextIPsWithRangeConstraints("test-hyphenated")
			require.NoError(t, err)
			require.Len(t, ips, 1)

			ip := ips[0].IP
			ipBytes := ip.To4()
			require.NotNil(t, ipBytes)

			// Convert to uint32 for comparison
			ipVal := uint32(ipBytes[0])<<24 | uint32(ipBytes[1])<<16 | uint32(ipBytes[2])<<8 | uint32(ipBytes[3])
			startVal := uint32(192)<<24 | uint32(168)<<16 | uint32(1)<<8 | uint32(10)
			endVal := uint32(192)<<24 | uint32(168)<<16 | uint32(1)<<8 | uint32(15)

			assert.GreaterOrEqual(t, ipVal, startVal, "IP %s should be >= 192.168.1.10", ip)
			assert.LessOrEqual(t, ipVal, endVal, "IP %s should be <= 192.168.1.15", ip)

			t.Logf("Allocated IP %d: %s", i+1, ip.String())
		}
	})

	t.Run("Single IP range allocation", func(t *testing.T) {
		// Test single IP using a /30 subnet but with single IP constraint
		// This gives us a subnet with multiple IPs but constrains allocation to just one
		singleAllocator := NewAllocator()
		addresses := []string{"192.168.2.100-192.168.2.100"} // Single IP via hyphenated range
		subnets, constraints, err := ParseIPRangesWithConstraints(addresses)
		require.NoError(t, err)

		config := SubnetConfig{
			Name:             "test-single-ip",
			Subnets:          subnets,
			RangeConstraints: constraints,
		}

		err = singleAllocator.AddOrUpdateSubnet(config)
		require.NoError(t, err)

		// Allocate IP and verify it's exactly the specified one
		ips, err := singleAllocator.AllocateNextIPsWithRangeConstraints("test-single-ip")
		require.NoError(t, err)
		require.Len(t, ips, 1)

		assert.Equal(t, "192.168.2.100", ips[0].IP.String())
		t.Logf("Allocated single IP: %s", ips[0].IP.String())

		// Second allocation should fail after max attempts (since only one IP is in constraint)
		_, err = singleAllocator.AllocateNextIPsWithRangeConstraints("test-single-ip")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "after 1000 attempts")
	})

	t.Run("CIDR range allocation works normally", func(t *testing.T) {
		// Test CIDR: 192.168.3.0/30 (4 IPs: .0, .1, .2, .3)
		addresses := []string{"192.168.3.0/30"}
		subnets, constraints, err := ParseIPRangesWithConstraints(addresses)
		require.NoError(t, err)

		config := SubnetConfig{
			Name:             "test-cidr",
			Subnets:          subnets,
			RangeConstraints: constraints,
		}

		err = allocator.AddOrUpdateSubnet(config)
		require.NoError(t, err)

		// Allocate IP and verify it's within the CIDR
		ips, err := allocator.AllocateNextIPsWithRangeConstraints("test-cidr")
		require.NoError(t, err)
		require.Len(t, ips, 1)

		ip := ips[0].IP.String()
		// Should get first allocatable IP (typically .1 as .0 might be reserved)
		assert.Contains(t, []string{"192.168.3.0", "192.168.3.1", "192.168.3.2", "192.168.3.3"}, ip)
		t.Logf("Allocated CIDR IP: %s", ip)
	})

	t.Run("Mixed range types", func(t *testing.T) {
		// Test multiple range types: CIDR + hyphenated + single IP
		// Use a fresh allocator instance for this test to avoid conflicts
		mixedAllocator := NewAllocator()
		addresses := []string{
			"192.168.14.0/29",       // CIDR (8 IPs)
			"192.168.15.10-192.168.15.12", // Hyphenated (3 IPs)
			"192.168.16.50-192.168.16.50",  // Single IP via hyphenated range
		}
		subnets, constraints, err := ParseIPRangesWithConstraints(addresses)
		require.NoError(t, err)

		config := SubnetConfig{
			Name:             "test-mixed-ranges",
			Subnets:          subnets,
			RangeConstraints: constraints,
		}

		err = mixedAllocator.AddOrUpdateSubnet(config)
		require.NoError(t, err)

		// Allocate IPs and verify one from each range type
		ips, err := mixedAllocator.AllocateNextIPsWithRangeConstraints("test-mixed-ranges")
		require.NoError(t, err)
		require.Len(t, ips, 3)

		// Should get one IP from each subnet
		ip1 := ips[0].IP.String()
		ip2 := ips[1].IP.String()
		ip3 := ips[2].IP.String()

		t.Logf("Mixed allocation - CIDR: %s, Hyphenated: %s, Single: %s", ip1, ip2, ip3)

		// Verify IPs are from correct ranges
		assert.True(t, constraints[0].Contains(ips[0].IP), "IP %s should be in CIDR range", ip1)
		assert.True(t, constraints[1].Contains(ips[1].IP), "IP %s should be in hyphenated range", ip2)
		assert.True(t, constraints[2].Contains(ips[2].IP), "IP %s should be in single IP range", ip3)

		// Verify specific IPs
		assert.True(t, ips[1].IP.String() >= "192.168.15.10" && ips[1].IP.String() <= "192.168.15.12", "Hyphenated IP should be in range")
		assert.Equal(t, "192.168.16.50", ip3, "Single IP should be exactly 192.168.16.50")
	})

	t.Run("Fallback to regular allocation when no constraints", func(t *testing.T) {
		// Test without range constraints (backward compatibility)
		addresses := []string{"192.168.7.0/28"}
		subnets, _, err := ParseIPRangesWithConstraints(addresses)
		require.NoError(t, err)

		config := SubnetConfig{
			Name:             "test-no-constraints",
			Subnets:          subnets,
			RangeConstraints: nil, // No constraints
		}

		err = allocator.AddOrUpdateSubnet(config)
		require.NoError(t, err)

		// Should still work without range constraints
		ips, err := allocator.AllocateNextIPsWithRangeConstraints("test-no-constraints")
		require.NoError(t, err)
		require.Len(t, ips, 1)

		t.Logf("No constraints allocation: %s", ips[0].IP.String())
	})
}

func TestRangeConstraintValidation(t *testing.T) {
	t.Run("IPv6 hyphenated range validation", func(t *testing.T) {
		// Valid IPv6 range within same /64
		constraint, err := parseHyphenatedRangeWithConstraint("fc00:f853:ccd:e799::1-fc00:f853:ccd:e799::5")
		require.NoError(t, err)
		assert.Equal(t, RangeTypeHyphenated, constraint.Type)
		assert.Equal(t, "fc00:f853:ccd:e799::1", constraint.StartIP.String())
		assert.Equal(t, "fc00:f853:ccd:e799::5", constraint.EndIP.String())

		// Test Contains method
		assert.True(t, constraint.Contains(net.ParseIP("fc00:f853:ccd:e799::3")))
		assert.False(t, constraint.Contains(net.ParseIP("fc00:f853:ccd:e799::10")))
	})

	t.Run("IPv6 range across different /64 should fail", func(t *testing.T) {
		_, err := parseHyphenatedRangeWithConstraint("fc00:f853:ccd:e799::1-fc00:f853:ccd:e800::1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "only supported within the same /64 subnet")
	})

	t.Run("Mixed IP version range should fail", func(t *testing.T) {
		_, err := parseHyphenatedRangeWithConstraint("192.168.1.1-fc00::1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be the same version")
	})

	t.Run("Inverted range should fail", func(t *testing.T) {
		_, err := parseHyphenatedRangeWithConstraint("192.168.1.10-192.168.1.5")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "is greater than end IP")
	})
}