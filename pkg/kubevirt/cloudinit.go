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
	"gopkg.in/yaml.v2"
)

// CloudInitNetworkDataV2 represents cloud-init network data version 2
type CloudInitNetworkDataV2 struct {
	Version   int                      `json:"version" yaml:"version"`
	Ethernets map[string]EthernetConfig `json:"ethernets" yaml:"ethernets"`
}

// EthernetConfig represents the configuration for an ethernet interface
type EthernetConfig struct {
	Addresses   []string      `json:"addresses,omitempty" yaml:"addresses,omitempty"`
	Gateway4    string        `json:"gateway4,omitempty" yaml:"gateway4,omitempty"`
	Gateway6    string        `json:"gateway6,omitempty" yaml:"gateway6,omitempty"`
	Nameservers NameserverConfig `json:"nameservers,omitempty" yaml:"nameservers,omitempty"`
}

// NameserverConfig represents DNS nameserver configuration
type NameserverConfig struct {
	Addresses []string `json:"addresses,omitempty" yaml:"addresses,omitempty"`
}

// GenerateCloudInitNetworkDataV2 generates cloud-init network data version 2 JSON
// from user-provided network data with allocated IP addresses injected
func GenerateCloudInitNetworkDataV2(config *infrav1.VirtualMachineBootstrapNetworkConfig, allocatedIPs []*net.IPNet) (string, error) {
	if config == nil {
		return "", fmt.Errorf("bootstrap network configuration is nil")
	}

	// If user provided custom network data, use it and inject allocated IPs
	if config.NetworkData != nil && *config.NetworkData != "" {
		return injectAllocatedIPsIntoNetworkData(*config.NetworkData, config.Interface, allocatedIPs)
	}

	// Fallback: generate basic network configuration (for backward compatibility)
	networkData := CloudInitNetworkDataV2{
		Version:   2,
		Ethernets: make(map[string]EthernetConfig),
	}

	interfaceName := config.Interface
	if interfaceName == "" {
		interfaceName = "enp1s0" // default interface name
	}

	ethernetConfig := EthernetConfig{}

	// Add allocated IP addresses
	if len(allocatedIPs) > 0 {
		addresses := make([]string, 0, len(allocatedIPs))
		for _, ipNet := range allocatedIPs {
			if ipNet != nil {
				addresses = append(addresses, ipNet.String())
			}
		}
		ethernetConfig.Addresses = addresses
	}

	networkData.Ethernets[interfaceName] = ethernetConfig

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(networkData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal network data to JSON: %w", err)
	}

	return string(jsonData), nil
}

// GenerateCloudInitNetworkDataV2Base64 generates base64-encoded cloud-init network data version 2
func GenerateCloudInitNetworkDataV2Base64(config *infrav1.VirtualMachineBootstrapNetworkConfig, allocatedIPs []*net.IPNet) (string, error) {
	jsonData, err := GenerateCloudInitNetworkDataV2(config, allocatedIPs)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString([]byte(jsonData)), nil
}

// GenerateCloudInitNetworkDataV2YAML generates cloud-init network data version 2 YAML
// from user-provided network data with allocated IP addresses injected
func GenerateCloudInitNetworkDataV2YAML(config *infrav1.VirtualMachineBootstrapNetworkConfig, allocatedIPs []*net.IPNet) (string, error) {
	if config == nil {
		return "", fmt.Errorf("bootstrap network configuration is nil")
	}

	// If user provided custom network data, use it and inject allocated IPs
	if config.NetworkData != nil && *config.NetworkData != "" {
		return injectAllocatedIPsIntoNetworkDataYAML(*config.NetworkData, config.Interface, allocatedIPs)
	}

	// Fallback: generate basic network configuration (for backward compatibility)
	networkData := CloudInitNetworkDataV2{
		Version:   2,
		Ethernets: make(map[string]EthernetConfig),
	}

	interfaceName := config.Interface
	if interfaceName == "" {
		interfaceName = "enp1s0" // default interface name
	}

	ethernetConfig := EthernetConfig{}

	// Add allocated IP addresses
	if len(allocatedIPs) > 0 {
		addresses := make([]string, 0, len(allocatedIPs))
		for _, ipNet := range allocatedIPs {
			if ipNet != nil {
				addresses = append(addresses, ipNet.String())
			}
		}
		ethernetConfig.Addresses = addresses
	}

	networkData.Ethernets[interfaceName] = ethernetConfig

	// Marshal to YAML
	yamlData, err := yaml.Marshal(networkData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal network data to YAML: %w", err)
	}

	return string(yamlData), nil
}

// GenerateCloudInitNetworkDataV2YAMLBase64 generates base64-encoded cloud-init network data version 2 YAML
func GenerateCloudInitNetworkDataV2YAMLBase64(config *infrav1.VirtualMachineBootstrapNetworkConfig, allocatedIPs []*net.IPNet) (string, error) {
	yamlData, err := GenerateCloudInitNetworkDataV2YAML(config, allocatedIPs)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString([]byte(yamlData)), nil
}

// injectAllocatedIPsIntoNetworkData takes user-provided cloud-init network data
// and injects allocated IP addresses into the specified interface
func injectAllocatedIPsIntoNetworkData(userNetworkData, interfaceName string, allocatedIPs []*net.IPNet) (string, error) {
	if len(allocatedIPs) == 0 {
		return userNetworkData, nil
	}

	// Default interface name if not specified
	if interfaceName == "" {
		interfaceName = "enp1s0"
	}

	// Parse user-provided YAML network data
	var networkData CloudInitNetworkDataV2
	if err := yaml.Unmarshal([]byte(userNetworkData), &networkData); err != nil {
		return "", fmt.Errorf("failed to parse user network data as YAML: %w", err)
	}

	// Ensure the network data has the required structure
	if networkData.Ethernets == nil {
		networkData.Ethernets = make(map[string]EthernetConfig)
	}

	// Get existing configuration for the interface
	ethernetConfig, exists := networkData.Ethernets[interfaceName]
	if !exists {
		ethernetConfig = EthernetConfig{}
	}

	// Inject allocated IP addresses
	addresses := make([]string, 0, len(allocatedIPs))
	for _, ipNet := range allocatedIPs {
		if ipNet != nil {
			addresses = append(addresses, ipNet.String())
		}
	}
	ethernetConfig.Addresses = addresses

	// Update the configuration
	networkData.Ethernets[interfaceName] = ethernetConfig

	// Ensure version is set
	if networkData.Version == 0 {
		networkData.Version = 2
	}

	// Marshal back to JSON
	jsonData, err := json.MarshalIndent(networkData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal modified network data to JSON: %w", err)
	}

	return string(jsonData), nil
}

// injectAllocatedIPsIntoNetworkDataYAML takes user-provided cloud-init network data
// and injects allocated IP addresses into the specified interface, returning YAML
func injectAllocatedIPsIntoNetworkDataYAML(userNetworkData, interfaceName string, allocatedIPs []*net.IPNet) (string, error) {
	if len(allocatedIPs) == 0 {
		return userNetworkData, nil
	}

	// Default interface name if not specified
	if interfaceName == "" {
		interfaceName = "enp1s0"
	}

	// Parse user-provided YAML network data
	var networkData CloudInitNetworkDataV2
	if err := yaml.Unmarshal([]byte(userNetworkData), &networkData); err != nil {
		return "", fmt.Errorf("failed to parse user network data as YAML: %w", err)
	}

	// Ensure the network data has the required structure
	if networkData.Ethernets == nil {
		networkData.Ethernets = make(map[string]EthernetConfig)
	}

	// Get existing configuration for the interface
	ethernetConfig, exists := networkData.Ethernets[interfaceName]
	if !exists {
		ethernetConfig = EthernetConfig{}
	}

	// Inject allocated IP addresses
	addresses := make([]string, 0, len(allocatedIPs))
	for _, ipNet := range allocatedIPs {
		if ipNet != nil {
			addresses = append(addresses, ipNet.String())
		}
	}
	ethernetConfig.Addresses = addresses

	// Update the configuration
	networkData.Ethernets[interfaceName] = ethernetConfig

	// Ensure version is set
	if networkData.Version == 0 {
		networkData.Version = 2
	}

	// Marshal back to YAML
	yamlData, err := yaml.Marshal(networkData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal modified network data to YAML: %w", err)
	}

	return string(yamlData), nil
}