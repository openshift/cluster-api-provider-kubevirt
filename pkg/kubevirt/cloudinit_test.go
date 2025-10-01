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

func TestEnsureCloudInitNetworkDataV2WithAllocatedIPs(t *testing.T) {
	config := &infrav1.NetworkConfig{
		CloudInitNetworkData: `{
  "links": [
    {
      "id": "enp1s0",
      "type": "physical",
      "name": "enp1s0"
    }
  ],
  "networks": [
    {
      "id": "network0",
      "type": "ipv4",
      "link": "enp1s0",
      "netmask": "255.255.255.240",
      "gateway": "192.168.100.1",
      "routes": [
        {
          "network": "0.0.0.0",
          "netmask": "0.0.0.0",
          "gateway": "192.168.100.1"
        }
      ]
    }
  ],
  "services": [
    {
      "type": "dns",
      "address": "8.8.8.8"
    }
  ]
}`,
		IPPool: map[string]infrav1.IPPoolEntry{
			"tenant-bridge-net": {
				InterfaceName: "enp1s0",
				Subnets:       []string{"192.168.100.5-192.168.100.8"},
			},
		},
	}

	allocatedIPsByNetwork := map[string][]*net.IPNet{
		"tenant-bridge-net": {
			{
				IP:   net.ParseIP("192.168.100.5"),
				Mask: net.CIDRMask(28, 32),
			},
		},
	}

	result, err := EnsureCloudInitNetworkDataV2WithAllocatedIPs(config, allocatedIPsByNetwork)
	require.NoError(t, err)
	require.NotEmpty(t, result)

	// Basic checks to ensure the result contains expected elements in OpenStack format
	// Since there's already a network config for enp1s0, allocated IP should be added to existing network
	assert.Contains(t, result, "192.168.100.5") // allocated IP should be added to existing network
	assert.NotContains(t, result, "enp1s0-allocated-0") // allocated network ID should not be added (since we're updating existing)
	assert.Contains(t, result, "enp1s0")
	assert.Contains(t, result, "8.8.8.8") // original DNS
	assert.Contains(t, result, "192.168.100.1") // original gateway
	assert.Contains(t, result, "\"links\":")
	assert.Contains(t, result, "\"networks\":")
	assert.Contains(t, result, "\"services\":")
	assert.Contains(t, result, "\"type\": \"physical\"")
	assert.Contains(t, result, "\"type\": \"ipv4\"")
	assert.Contains(t, result, "\"type\": \"dns\"")
	assert.Contains(t, result, "\"name\": \"enp1s0\"") // ensure name field is preserved
	assert.Contains(t, result, "\"routes\"") // ensure routes are preserved
	assert.Contains(t, result, "0.0.0.0") // ensure route details are preserved
}

func TestEnsureCloudInitNetworkDataV2WithAllocatedIPsNewInterface(t *testing.T) {
	config := &infrav1.NetworkConfig{
		CloudInitNetworkData: `{
  "links": [
    {
      "id": "enp1s0",
      "type": "physical",
      "name": "enp1s0"
    }
  ],
  "networks": [
    {
      "id": "network0",
      "type": "ipv4",
      "link": "enp1s0",
      "netmask": "255.255.255.240",
      "gateway": "192.168.100.1"
    }
  ],
  "services": [
    {
      "type": "dns",
      "address": "8.8.8.8"
    }
  ]
}`,
		IPPool: map[string]infrav1.IPPoolEntry{
			"tenant-bridge-net": {
				InterfaceName: "enp2s0", // Different interface that doesn't have existing network config
				Subnets:       []string{"192.168.200.5-192.168.200.8"},
			},
		},
	}

	allocatedIPsByNetwork := map[string][]*net.IPNet{
		"tenant-bridge-net": {
			{
				IP:   net.ParseIP("192.168.200.5"),
				Mask: net.CIDRMask(28, 32),
			},
		},
	}

	result, err := EnsureCloudInitNetworkDataV2WithAllocatedIPs(config, allocatedIPsByNetwork)
	require.NoError(t, err)
	require.NotEmpty(t, result)

	// Since enp2s0 has no existing network config, allocated IPs should be added
	assert.Contains(t, result, "192.168.200.5") // allocated IP should be added
	assert.Contains(t, result, "enp2s0-allocated-0") // allocated network ID should be added
	assert.Contains(t, result, "enp2s0") // new interface should be present
	assert.Contains(t, result, "enp1s0") // original interface should still be present
	assert.Contains(t, result, "8.8.8.8") // original DNS
	assert.Contains(t, result, "192.168.100.1") // original gateway
}

func TestEnsureCloudInitNetworkDataV2WithAllocatedIPsBase64(t *testing.T) {
	config := &infrav1.NetworkConfig{
		CloudInitNetworkData: `{
  "links": [
    {
      "id": "enp1s0",
      "type": "physical",
      "name": "enp1s0"
    }
  ],
  "networks": [
    {
      "id": "network0",
      "type": "ipv4",
      "link": "enp1s0",
      "netmask": "255.255.255.240",
      "gateway": "192.168.100.1"
    }
  ],
  "services": [
    {
      "type": "dns",
      "address": "8.8.8.8"
    }
  ]
}`,
		IPPool: map[string]infrav1.IPPoolEntry{
			"tenant-bridge-net": {
				InterfaceName: "enp1s0",
				Subnets:       []string{"192.168.100.5-192.168.100.8"},
			},
		},
	}

	allocatedIPsByNetwork := map[string][]*net.IPNet{
		"tenant-bridge-net": {
			{
				IP:   net.ParseIP("192.168.100.5"),
				Mask: net.CIDRMask(28, 32),
			},
		},
	}

	result, err := EnsureCloudInitNetworkDataV2WithAllocatedIPsBase64(config, allocatedIPsByNetwork)
	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestEnsureCloudInitNetworkDataV2WithAllocatedIPsError(t *testing.T) {
	// Test nil config
	_, err := EnsureCloudInitNetworkDataV2WithAllocatedIPs(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "network configuration is nil")

	// Test empty CloudInitNetworkData
	config := &infrav1.NetworkConfig{
		CloudInitNetworkData: "",
		IPPool: map[string]infrav1.IPPoolEntry{
			"default-network": {
				InterfaceName: "enp1s0",
				Subnets:       []string{"192.168.1.0/24"},
			},
		},
	}

	_, err = EnsureCloudInitNetworkDataV2WithAllocatedIPs(config, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CloudInitNetworkData is required")
}

func TestEnsureCloudInitNetworkDataV2WithTemplateConfig(t *testing.T) {
	// This test uses the exact configuration from templates/cluster-template-multus-ippool.yaml
	config := &infrav1.NetworkConfig{
		CloudInitNetworkData: `{
  "links": [
    {
      "id": "enp1s0",
      "type": "physical",
      "name": "enp1s0"
    }
  ],
  "networks": [
    {
      "id": "network0",
      "type": "ipv4",
      "link": "enp1s0",
      "routes": [{
        "network": "0.0.0.0",
        "netmask": "0.0.0.0",
        "gateway": "192.168.123.1"
      }]
    }
  ],
  "services": [
    {
      "type": "dns",
      "address": "192.168.123.1"
    }
  ]
}`,
		IPPool: map[string]infrav1.IPPoolEntry{
			"tenant-bridge-net": {
				InterfaceName: "enp1s0",
				Subnets:       []string{"192.168.123.100-192.168.123.200"},
			},
		},
	}

	allocatedIPsByNetwork := map[string][]*net.IPNet{
		"tenant-bridge-net": {
			{
				IP:   net.ParseIP("192.168.123.100"),
				Mask: net.CIDRMask(24, 32),
			},
		},
	}

	result, err := EnsureCloudInitNetworkDataV2WithAllocatedIPs(config, allocatedIPsByNetwork)
	require.NoError(t, err)
	require.NotEmpty(t, result)

	// Verify all template elements are preserved
	assert.Contains(t, result, "\"id\": \"enp1s0\"")
	assert.Contains(t, result, "\"type\": \"physical\"")
	assert.Contains(t, result, "\"name\": \"enp1s0\"")

	// Verify network configuration
	assert.Contains(t, result, "\"id\": \"network0\"")
	assert.Contains(t, result, "\"type\": \"ipv4\"")
	assert.Contains(t, result, "\"link\": \"enp1s0\"")

	// Verify allocated IP was injected
	assert.Contains(t, result, "192.168.123.100")

	// Verify routes are preserved
	assert.Contains(t, result, "\"routes\"")
	assert.Contains(t, result, "\"network\": \"0.0.0.0\"")
	assert.Contains(t, result, "\"netmask\": \"0.0.0.0\"")
	assert.Contains(t, result, "\"gateway\": \"192.168.123.1\"")

	// Verify services are preserved
	assert.Contains(t, result, "\"services\"")
	assert.Contains(t, result, "\"type\": \"dns\"")
	assert.Contains(t, result, "\"address\": \"192.168.123.1\"")
}