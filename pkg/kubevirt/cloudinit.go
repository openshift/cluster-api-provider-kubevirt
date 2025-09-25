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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"

	infrav1 "sigs.k8s.io/cluster-api-provider-kubevirt/api/v1alpha1"
)

// CloudInitNetworkDataV2 represents cloud-init network data version 2 (netplan format)
type CloudInitNetworkDataV2 struct {
	Version   int                      `json:"version"`
	Ethernets map[string]EthernetConfig `json:"ethernets"`
}

// EthernetConfig represents the configuration for an ethernet interface in netplan format
type EthernetConfig struct {
	Addresses   []string      `json:"addresses,omitempty"`
	Gateway4    string        `json:"gateway4,omitempty"`
	Gateway6    string        `json:"gateway6,omitempty"`
	Nameservers NameserverConfig `json:"nameservers,omitempty"`
}

// NameserverConfig represents DNS nameserver configuration
type NameserverConfig struct {
	Addresses []string `json:"addresses,omitempty"`
}

// OpenStackNetworkData represents OpenStack network data format for KubeVirt config drive
type OpenStackNetworkData struct {
	Links    []NetworkLink    `json:"links"`
	Networks []NetworkConfig `json:"networks"`
	Services []NetworkService `json:"services,omitempty"`
}

// NetworkLink represents a network link in OpenStack format
type NetworkLink struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Name         string `json:"name,omitempty"`
	EthernetMacAddress string `json:"ethernet_mac_address,omitempty"`
}

// NetworkRoute represents a network route in OpenStack format
type NetworkRoute struct {
	Network string `json:"network"`
	Netmask string `json:"netmask"`
	Gateway string `json:"gateway"`
}

// NetworkConfig represents a network configuration in OpenStack format
type NetworkConfig struct {
	ID        string         `json:"id"`
	Link      string         `json:"link"`
	Type      string         `json:"type"`
	IPAddress string         `json:"ip_address,omitempty"`
	Netmask   string         `json:"netmask,omitempty"`
	Gateway   string         `json:"gateway,omitempty"`
	Routes    []NetworkRoute `json:"routes,omitempty"`
}

// NetworkService represents DNS service configuration in OpenStack format
type NetworkService struct {
	Type    string `json:"type"`
	Address string `json:"address"`
}

// EnsureCloudInitNetworkDataV2WithAllocatedIPs ensures that the provided cloud-init network data
// contains the specified interfaces with their allocated IP addresses
func EnsureCloudInitNetworkDataV2WithAllocatedIPs(config *infrav1.NetworkConfig, allocatedIPsByNetwork map[string][]*net.IPNet) (string, error) {
	if config == nil {
		return "", fmt.Errorf("network configuration is nil")
	}

	if config.CloudInitNetworkData == "" {
		return "", fmt.Errorf("CloudInitNetworkData is required")
	}

	return ensureAllocatedIPsInNetworkData(config.CloudInitNetworkData, config.IPPool, allocatedIPsByNetwork)
}

// EnsureCloudInitNetworkDataV2WithAllocatedIPsBase64 ensures allocated IPs and returns base64-encoded result
func EnsureCloudInitNetworkDataV2WithAllocatedIPsBase64(config *infrav1.NetworkConfig, allocatedIPsByNetwork map[string][]*net.IPNet) (string, error) {
	jsonData, err := EnsureCloudInitNetworkDataV2WithAllocatedIPs(config, allocatedIPsByNetwork)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString([]byte(jsonData)), nil
}


// ensureAllocatedIPsInNetworkData ensures that the specified interfaces exist in the network data
// and have their allocated IP addresses added to the existing network configuration
func ensureAllocatedIPsInNetworkData(userNetworkData string, ipPool map[string]infrav1.IPPoolEntry, allocatedIPsByNetwork map[string][]*net.IPNet) (string, error) {
	// Parse user-provided network data as OpenStack format
	var openstackData OpenStackNetworkData
	if err := json.Unmarshal([]byte(userNetworkData), &openstackData); err != nil {
		return "", fmt.Errorf("failed to parse user network data as JSON: %w", err)
	}

	// Process each network in the IPPool and add allocated IP addresses
	for networkName, poolEntry := range ipPool {
		interfaceName := poolEntry.InterfaceName
		allocatedIPs := allocatedIPsByNetwork[networkName]

		if len(allocatedIPs) == 0 {
			continue
		}

		// Find or create the link for this interface
		linkID := interfaceName
		linkExists := false
		for _, link := range openstackData.Links {
			if link.ID == linkID {
				linkExists = true
				break
			}
		}
		if !linkExists {
			link := NetworkLink{
				ID:   linkID,
				Type: "physical",
				Name: interfaceName,
			}
			openstackData.Links = append(openstackData.Links, link)
		}

		// Find existing network configurations for this interface
		existingNetworkFound := false
		for i, network := range openstackData.Networks {
			if network.Link == linkID {
				existingNetworkFound = true
				// Add allocated IP to existing network configuration if it doesn't have one
				if network.IPAddress == "" && len(allocatedIPs) > 0 && allocatedIPs[0] != nil {
					openstackData.Networks[i].IPAddress = allocatedIPs[0].IP.String()
				}
				break
			}
		}

		// Only add new network configurations if there isn't already a network config for this interface
		if !existingNetworkFound {
			// Add allocated IP addresses to the interface
			for i, ipNet := range allocatedIPs {
				if ipNet != nil {
					networkID := fmt.Sprintf("%s-allocated-%d", interfaceName, i)

					// Create new network configuration for the allocated IP
					networkConfig := NetworkConfig{
						ID:        networkID,
						Link:      linkID,
						Type:      "ipv4",
						IPAddress: ipNet.IP.String(),
						Netmask:   net.IP(ipNet.Mask).String(),
					}

					openstackData.Networks = append(openstackData.Networks, networkConfig)
				}
			}
		}
	}

	// Marshal back to JSON
	jsonData, err := json.MarshalIndent(openstackData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal network data to JSON: %w", err)
	}

	return string(jsonData), nil
}

