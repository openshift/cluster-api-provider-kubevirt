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
			name: "basic configuration with allocated IPs (no user network data)",
			config: &infrav1.VirtualMachineBootstrapNetworkConfig{
				Interface:   "enp1s0",
				NetworkName: "default-network",
				Subnets:     []string{"192.168.1.0/24"},
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
      "nameservers": {}
    }
  }
}`,
			expectError: false,
		},
		{
			name: "user-provided network data with IP injection",
			config: &infrav1.VirtualMachineBootstrapNetworkConfig{
				Interface:   "eth0",
				NetworkName: "user-network",
				Subnets:     []string{"10.0.0.0/24"},
				NetworkData: func() *string {
					data := `version: 2
ethernets:
  eth0:
    gateway4: "10.0.0.1"
    nameservers:
      addresses: ["8.8.8.8", "8.8.4.4"]`
					return &data
				}(),
			},
			allocatedIPs: []*net.IPNet{
				{
					IP:   net.ParseIP("10.0.0.100"),
					Mask: net.CIDRMask(24, 32),
				},
			},
			expected: `{
  "version": 2,
  "ethernets": {
    "eth0": {
      "addresses": [
        "10.0.0.100/24"
      ],
      "gateway4": "10.0.0.1",
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
			name: "configuration without allocated IPs (fallback mode)",
			config: &infrav1.VirtualMachineBootstrapNetworkConfig{
				Interface:   "enp1s0",
				NetworkName: "fallback-network",
				Subnets:     []string{"192.168.1.0/24"},
			},
			allocatedIPs: nil,
			expected: `{
  "version": 2,
  "ethernets": {
    "enp1s0": {
      "nameservers": {}
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
		Subnets:     []string{"192.168.1.0/24"},
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