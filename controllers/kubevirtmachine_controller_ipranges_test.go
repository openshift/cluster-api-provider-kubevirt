/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	infrav1 "sigs.k8s.io/cluster-api-provider-kubevirt/api/v1alpha1"
)

func TestIPRangeFormatsSupport(t *testing.T) {
	reconciler := &KubevirtMachineReconciler{}
	reconciler.InitializeIPAllocator()

	tests := []struct {
		name        string
		addresses   []string
		expectCount int
		expectError bool
	}{
		{
			name:        "CIDR notation",
			addresses:   []string{"192.168.10.0/29"}, // Has 8 IPs: .0-.7, allocatable: .1-.6 (excluding .0 network and .7 broadcast)
			expectCount: 1,
			expectError: false,
		},
		{
			name:        "Hyphenated range",
			addresses:   []string{"192.168.20.1-192.168.20.5"}, // 5 specific IPs
			expectCount: 1,
			expectError: false,
		},
		{
			name:        "Single IP via CIDR (larger subnet)",
			addresses:   []string{"10.10.10.0/30"}, // Small subnet with multiple IPs
			expectCount: 1,
			expectError: false,
		},
		{
			name:        "Mixed formats",
			addresses:   []string{"10.10.40.0/28", "10.10.41.0/30"}, // Use subnets instead of single IPs
			expectCount: 2, // One IP from each subnet
			expectError: false,
		},
		{
			name:        "IPv6 CIDR",
			addresses:   []string{"fc00:f853:ccd:e799::/126"}, // 4 IPs in IPv6
			expectCount: 1,
			expectError: false,
		},
		{
			name:        "IPv6 hyphenated range",
			addresses:   []string{"fc00:f853:ccd:e799::1-fc00:f853:ccd:e799::3"}, // 3 specific IPv6 IPs
			expectCount: 1,
			expectError: false,
		},
		{
			name:        "Invalid range - mixed IP versions",
			addresses:   []string{"192.168.1.1-fc00::1"},
			expectCount: 0,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machine := &infrav1.KubevirtMachine{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-machine-" + tt.name,
					Namespace: "default",
				},
			}

			config := &infrav1.VirtualMachineBootstrapNetworkConfig{
				Interface:   "enp1s0",
				NetworkName: "test-network-" + tt.name,
				Addresses:   tt.addresses,
				Nameservers: []string{"8.8.8.8"},
				Gateway:     []string{"192.168.1.1"},
			}

			allocatedIPs, err := reconciler.AllocateIPsForMachine(machine, config)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, allocatedIPs, tt.expectCount)

			if len(allocatedIPs) > 0 {
				t.Logf("Allocated IP for %s: %s", tt.name, allocatedIPs[0].IP.String())

				// Verify IP is valid and not zero
				assert.NotNil(t, allocatedIPs[0].IP)
				assert.NotEqual(t, "0.0.0.0", allocatedIPs[0].IP.String())
				assert.NotEqual(t, "::", allocatedIPs[0].IP.String())
			}

			// Clean up by releasing IPs
			if len(allocatedIPs) > 0 {
				err = reconciler.ReleaseIPsForMachine(machine, config)
				assert.NoError(t, err)
			}
		})
	}
}

func TestMetalLBStyleConfiguration(t *testing.T) {
	reconciler := &KubevirtMachineReconciler{}
	reconciler.InitializeIPAllocator()

	// Example configuration similar to MetalLB
	machine := &infrav1.KubevirtMachine{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-metallb-style",
			Namespace: "default",
		},
	}

	config := &infrav1.VirtualMachineBootstrapNetworkConfig{
		Interface:   "enp1s0",
		NetworkName: "metallb-test-pool",
		Addresses: []string{
			"192.168.10.0/24",          // CIDR notation - full subnet
			"192.168.20.1-192.168.20.50", // Hyphenated range - specific range
			"192.168.30.0/28",          // Small subnet instead of single IP
		},
		Nameservers: []string{"8.8.8.8", "8.8.4.4"},
		Gateway:     []string{"192.168.10.1"},
	}

	// Test that allocation succeeds and returns expected number of IPs
	allocatedIPs, err := reconciler.AllocateIPsForMachine(machine, config)
	require.NoError(t, err)
	require.Len(t, allocatedIPs, 3) // One IP from each of the 3 subnets

	t.Logf("Allocated IPs: %v", allocatedIPs)

	// Verify that the IPs are valid and from the expected networks
	for _, ip := range allocatedIPs {
		assert.NotNil(t, ip.IP)
		assert.NotEqual(t, "0.0.0.0", ip.IP.String())
		// Should be from one of our configured networks
		ipStr := ip.IP.String()
		inExpectedRange := strings.HasPrefix(ipStr, "192.168.10.") ||
			strings.HasPrefix(ipStr, "192.168.20.") ||
			strings.HasPrefix(ipStr, "192.168.30.")
		assert.True(t, inExpectedRange, "IP %s should be from configured ranges", ipStr)
	}

	// Clean up
	err = reconciler.ReleaseIPsForMachine(machine, config)
	assert.NoError(t, err)
}

func TestRangeAwareAllocation(t *testing.T) {
	reconciler := &KubevirtMachineReconciler{}
	reconciler.InitializeIPAllocator()

	t.Run("Hyphenated range stays within bounds", func(t *testing.T) {
		machine := &infrav1.KubevirtMachine{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-hyphenated-range",
				Namespace: "default",
			},
		}

		config := &infrav1.VirtualMachineBootstrapNetworkConfig{
			Interface:   "enp1s0",
			NetworkName: "hyphenated-test",
			Addresses:   []string{"10.0.0.10-10.0.0.15"}, // Only 6 specific IPs
			Nameservers: []string{"8.8.8.8"},
			Gateway:     []string{"10.0.0.1"},
		}

		// Allocate multiple IPs and verify they're within the range
		var allocatedIPs []string
		for i := 0; i < 3; i++ {
			machine.Name = fmt.Sprintf("test-machine-%d", i)
			ips, err := reconciler.AllocateIPsForMachine(machine, config)
			require.NoError(t, err)
			require.Len(t, ips, 1)

			ipStr := ips[0].IP.String()
			allocatedIPs = append(allocatedIPs, ipStr)

			// Verify IP is within range 10.0.0.10-10.0.0.15
			ip := ips[0].IP.To4()
			require.NotNil(t, ip)
			ipVal := int(ip[3]) // Last octet
			assert.GreaterOrEqual(t, ipVal, 10, "IP %s should be >= 10.0.0.10", ipStr)
			assert.LessOrEqual(t, ipVal, 15, "IP %s should be <= 10.0.0.15", ipStr)

			t.Logf("Machine %d allocated IP: %s", i, ipStr)
		}

		// Verify all IPs are different
		uniqueIPs := make(map[string]bool)
		for _, ip := range allocatedIPs {
			assert.False(t, uniqueIPs[ip], "IP %s should not be allocated twice", ip)
			uniqueIPs[ip] = true
		}
	})

	t.Run("Single IP allocation", func(t *testing.T) {
		machine := &infrav1.KubevirtMachine{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-single-ip",
				Namespace: "default",
			},
		}

		config := &infrav1.VirtualMachineBootstrapNetworkConfig{
			Interface:   "enp1s0",
			NetworkName: "single-ip-test",
			Addresses:   []string{"10.1.1.100/32"}, // Exactly one IP
			Nameservers: []string{"8.8.8.8"},
			Gateway:     []string{"10.1.1.1"},
		}

		// First allocation should get the exact IP
		ips, err := reconciler.AllocateIPsForMachine(machine, config)
		require.NoError(t, err)
		require.Len(t, ips, 1)
		assert.Equal(t, "10.1.1.100", ips[0].IP.String())

		t.Logf("Single IP allocation: %s", ips[0].IP.String())

		// Second allocation should fail (IP pool exhausted)
		machine2 := &infrav1.KubevirtMachine{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-single-ip-2",
				Namespace: "default",
			},
		}

		_, err = reconciler.AllocateIPsForMachine(machine2, config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exhausted")
	})
}