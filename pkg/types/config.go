/*******************************************************************************
 * Copyright 2019 Dell Inc.
 * Copyright 2021 Intel Corp.
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

package types

import (
	"fmt"
	"strings"
	"time"
)

// SecretConfig contains configuration settings used to communicate with an HTTP based secret provider
type SecretConfig struct {
	Type string
	Host string
	Port int
	// Path is the base path to the secret's location in the secret store
	Path                    string
	Protocol                string
	Namespace               string
	RootCaCertPath          string
	ServerName              string
	Authentication          AuthenticationInfo
	AdditionalRetryAttempts int
	RetryWaitPeriod         string
	RetryWaitPeriodTime     time.Duration
}

// BuildURL constructs a URL which can be used to identify a HTTP based secret provider
func (c SecretConfig) BuildURL(path string) string {
	// Make sure there is not a trailing slash
	if strings.HasSuffix(path, "/") {
		path = path[:len(path)-1]
	}

	return fmt.Sprintf("%s://%s:%v%s", c.Protocol, c.Host, c.Port, path)
}

// BuildSecretsPathURL constructs a URL which can be used to identify a secret's path
// subPath is the location of the secrets in the secrets engine
func (c SecretConfig) BuildSecretsPathURL(subPath string) string {
	return c.BuildURL(c.Path + subPath)
}

// AuthenticationInfo contains authentication information to be used when communicating with an HTTP based provider
type AuthenticationInfo struct {
	AuthType  string
	AuthToken string
}
