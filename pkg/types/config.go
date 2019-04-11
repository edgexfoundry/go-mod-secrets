/*******************************************************************************
 * Copyright 2019 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *******************************************************************************/

// Package types defines structs that will be used frequently in the codebase, both internal and external.
package types

// Config defines the information needed to connect to the secret provider and anything else a Client might need.
type Config struct {
	Provider       string
	Authentication AuthenticationInfo
	LogTarget      string
	LogLevel       string
	Service        ServiceInfo
	Target         TargetInfo
}

type AuthenticationInfo struct {
	AuthType  string
	AuthToken string
}

// ServiceInfo contains configuration settings necessary for the basic operation of any EdgeX service.
type ServiceInfo struct {
	// BootTimeout indicates, in milliseconds, how long the service will retry connecting to upstream dependencies
	// before giving up. Default is 30,000.
	BootTimeout int
	// Health check interval
	CheckInterval string
	// Indicates the interval in milliseconds at which service clients should check for any configuration updates
	ClientMonitor int
	// Host is the hostname or IP address of the service.
	Host string
	// Port is the HTTP port of the service.
	Port int
	// The protocol that should be used to call this service
	Protocol string
	// StartupMsg specifies a string to log once service
	// initialization and startup is completed.
	StartupMsg string
	// ReadMaxLimit specifies the maximum size list supported
	// in response to REST calls to other services.
	ReadMaxLimit int
	// Timeout specifies a timeout (in milliseconds) for
	// processing REST calls from other services.
	Timeout int
}

// TargetInfo describes the target of the client.
type TargetInfo struct {
	Host string `json:"host"`
	Port string `json:"port"`
	Path string `json:"path"`
}
