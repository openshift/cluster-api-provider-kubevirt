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

package kubevirt

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	infrav1 "sigs.k8s.io/cluster-api-provider-kubevirt/api/v1alpha1"
)

func TestGenerateCloudInitNetworkDataV2(t *testing.T) {
	tests := []struct {
		name         string
		config       *infrav1.VirtualMachineBootstrapNetworkConfig
		allocatedIPs []*net.IPNet
		expected     string
		expectError  bool
	}{
		{
			name: "basic configuration with allocated IPs",
			config: &infrav1.VirtualMachineBootstrapNetworkConfig{
				Interface:   "enp1s0",
				NetworkName: "default-network",
				Addresses:   []string{"192.168.1.0/24"},
				Nameservers: []string{"8.8.8.8", "8.8.4.4"},
				Gateway:     []string{"192.168.1.1"},
			},
			allocatedIPs: []*net.IPNet{
				{
					IP:   net.ParseIP("192.168.1.10"),
					Mask: net.CIDRMask(24, 32),
				},
			},
			expected: `{
  "version": 2,
  "ethernets": {
    "enp1s0": {
      "addresses": [
        "192.168.1.10/24"
      ],
      "gateway4": "192.168.1.1",
      "nameservers": {
        "addresses": [
          "8.8.8.8",
          "8.8.4.4"
        ]
      }
    }
  }
}`,
			expectError: false,
		},
		{
			name: "IPv6 configuration",
			config: &infrav1.VirtualMachineBootstrapNetworkConfig{
				Interface:   "eth0",
				NetworkName: "ipv6-network",
				Addresses:   []string{"2001:db8::/64"},
				Nameservers: []string{"2001:4860:4860::8888"},
				Gateway:     []string{"2001:db8::1"},
			},
			allocatedIPs: []*net.IPNet{
				{
					IP:   net.ParseIP("2001:db8::10"),
					Mask: net.CIDRMask(64, 128),
				},
			},
			expected: `{
  "version": 2,
  "ethernets": {
    "eth0": {
      "addresses": [
        "2001:db8::10/64"
      ],
      "gateway6": "2001:db8::1",
      "nameservers": {
        "addresses": [
          "2001:4860:4860::8888"
        ]
      }
    }
  }
}`,
			expectError: false,
		},
		{
			name: "configuration without allocated IPs falls back to configured addresses",
			config: &infrav1.VirtualMachineBootstrapNetworkConfig{
				Interface:   "enp1s0",
				NetworkName: "fallback-network",
				Addresses:   []string{"192.168.1.10/24"},
				Nameservers: []string{"8.8.8.8"},
				Gateway:     []string{"192.168.1.1"},
			},
			allocatedIPs: nil,
			expected: `{
  "version": 2,
  "ethernets": {
    "enp1s0": {
      "addresses": [
        "192.168.1.10/24"
      ],
      "gateway4": "192.168.1.1",
      "nameservers": {
        "addresses": [
          "8.8.8.8"
        ]
      }
    }
  }
}`,
			expectError: false,
		},
		{
			name:        "nil configuration should return error",
			config:      nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GenerateCloudInitNetworkDataV2(tt.config, tt.allocatedIPs)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateCloudInitNetworkDataV2Base64(t *testing.T) {
	config := &infrav1.VirtualMachineBootstrapNetworkConfig{
		Interface:   "enp1s0",
		NetworkName: "test-network",
		Addresses:   []string{"192.168.1.0/24"},
		Nameservers: []string{"8.8.8.8"},
		Gateway:     []string{"192.168.1.1"},
	}

	allocatedIPs := []*net.IPNet{
		{
			IP:   net.ParseIP("192.168.1.10"),
			Mask: net.CIDRMask(24, 32),
		},
	}

	result, err := GenerateCloudInitNetworkDataV2Base64(config, allocatedIPs)
	require.NoError(t, err)
	assert.NotEmpty(t, result)

	// The result should be base64 encoded
	// We could decode and verify, but for now just check it's not empty
	assert.True(t, len(result) > 0)
}