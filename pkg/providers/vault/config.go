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

// vault defines structs that will be used frequently by clients which utilize HTTP transport.
package vault

import (
	"fmt"
)

// SecretConfig contains configuration settings used to communicate with an HTTP based secret provider
type SecretConfig struct {
	Host           string
	Port           int
	Path           string
	Protocol       string
	Namespace      string
	RootCaCertPath string
	ServerName     string
	Authentication AuthenticationInfo
}

// BuildURL constructs a URL which can be used to identify a HTTP based secret provider
func (c SecretConfig) BuildURL() (path string) {
	return fmt.Sprintf("%s://%s:%v%s", c.Protocol, c.Host, c.Port, c.Path)
}

// AuthenticationInfo contains authentication information to be used when communicating with an HTTP based provider
type AuthenticationInfo struct {
	AuthType  string
	AuthToken string
}
