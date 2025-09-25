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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	infrav1 "sigs.k8s.io/cluster-api-provider-kubevirt/api/v1alpha1"
)

func TestAnnotationBasedIPAllocation(t *testing.T) {
	reconciler := &KubevirtMachineReconciler{}

	machine := &infrav1.KubevirtMachine{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-machine",
			Namespace: "default",
		},
	}

	networkName := "test-network"
	// Create IPNets correctly using ParseCIDR
	ip1, ipNet1, _ := net.ParseCIDR("192.168.1.10/24")
	ipNet1.IP = ip1
	ip2, ipNet2, _ := net.ParseCIDR("192.168.1.11/24")
	ipNet2.IP = ip2

	ips := []*net.IPNet{ipNet1, ipNet2}

	// Test setting allocated IPs annotation
	err := reconciler.setAllocatedIPsAnnotation(machine, networkName, ips)
	require.NoError(t, err)

	// Verify annotation was set
	expectedKey := getAllocatedIPsAnnotationKey(networkName)
	assert.Contains(t, machine.Annotations, expectedKey)

	// Test getting allocated IPs from annotation
	retrievedIPs, err := reconciler.getAllocatedIPsFromAnnotation(machine, networkName)
	require.NoError(t, err)
	require.Len(t, retrievedIPs, 2)

	// Verify IPs match
	assert.Equal(t, "192.168.1.10/24", retrievedIPs[0].String())
	assert.Equal(t, "192.168.1.11/24", retrievedIPs[1].String())

	// Test removing annotation
	reconciler.removeAllocatedIPsAnnotation(machine, networkName)
	assert.NotContains(t, machine.Annotations, expectedKey)

	// Test getting IPs after removal should return nil
	retrievedIPs, err = reconciler.getAllocatedIPsFromAnnotation(machine, networkName)
	require.NoError(t, err)
	assert.Nil(t, retrievedIPs)
}

func TestGetAllocatedIPsAnnotationKey(t *testing.T) {
	tests := []struct {
		networkName string
		expected    string
	}{
		{
			networkName: "test-network",
			expected:    "infrastructure.cluster.x-k8s.io/allocated-ips-test-network",
		},
		{
			networkName: "my-multus-net",
			expected:    "infrastructure.cluster.x-k8s.io/allocated-ips-my-multus-net",
		},
	}

	for _, tt := range tests {
		t.Run(tt.networkName, func(t *testing.T) {
			result := getAllocatedIPsAnnotationKey(tt.networkName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGatewayIPReservation(t *testing.T) {
	reconciler := &KubevirtMachineReconciler{}
	reconciler.InitializeIPAllocator()

	// Test IPv4 gateway exclusion
	machine1 := &infrav1.KubevirtMachine{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-machine-1",
			Namespace: "default",
		},
	}

	config := &infrav1.VirtualMachineBootstrapNetworkConfig{
		Interface:   "enp1s0",
		NetworkName: "test-gateway-network",
		Addresses:   []string{"192.168.100.0/24"},
		Nameservers: []string{"8.8.8.8"},
		Gateway:     []string{"192.168.100.1"}, // Gateway IP that should be excluded
	}

	// Allocation should not get the gateway IP
	allocatedIPs1, err := reconciler.AllocateIPsForMachine(machine1, config)
	require.NoError(t, err)
	require.Len(t, allocatedIPs1, 1)
	t.Logf("Machine got IP: %s", allocatedIPs1[0].IP.String())

	// The key test: ensure gateway IP is never allocated
	assert.NotEqual(t, "192.168.100.1", allocatedIPs1[0].IP.String())

	// Should get the first available IP after gateway (.2, since .0 is network, .1 is gateway)
	assert.Equal(t, "192.168.100.2", allocatedIPs1[0].IP.String())

	// Test IPv6 gateway exclusion with a separate network
	machine2 := &infrav1.KubevirtMachine{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-machine-2",
			Namespace: "default",
		},
	}

	configIPv6 := &infrav1.VirtualMachineBootstrapNetworkConfig{
		Interface:   "enp1s0",
		NetworkName: "test-ipv6-network",
		Addresses:   []string{"2001:db8::/64"},
		Nameservers: []string{"2001:4860:4860::8888"},
		Gateway:     []string{"2001:db8::1"}, // IPv6 gateway
	}

	allocatedIPs2, err := reconciler.AllocateIPsForMachine(machine2, configIPv6)
	require.NoError(t, err)
	require.Len(t, allocatedIPs2, 1)
	t.Logf("IPv6 machine got IP: %s", allocatedIPs2[0].IP.String())

	// Ensure IPv6 gateway is excluded
	assert.NotEqual(t, "2001:db8::1", allocatedIPs2[0].IP.String())

	// Test multiple gateways
	machine3 := &infrav1.KubevirtMachine{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-machine-3",
			Namespace: "default",
		},
	}

	configMultiGW := &infrav1.VirtualMachineBootstrapNetworkConfig{
		Interface:   "enp1s0",
		NetworkName: "test-multi-gw-network",
		Addresses:   []string{"10.0.0.0/24"},
		Nameservers: []string{"8.8.8.8"},
		Gateway:     []string{"10.0.0.1", "10.0.0.254"}, // Multiple gateways to exclude
	}

	allocatedIPs3, err := reconciler.AllocateIPsForMachine(machine3, configMultiGW)
	require.NoError(t, err)
	require.Len(t, allocatedIPs3, 1)
	t.Logf("Multi-gateway machine got IP: %s", allocatedIPs3[0].IP.String())

	// Ensure neither gateway IP is allocated
	assert.NotEqual(t, "10.0.0.1", allocatedIPs3[0].IP.String())
	assert.NotEqual(t, "10.0.0.254", allocatedIPs3[0].IP.String())
}