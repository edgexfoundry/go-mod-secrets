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

type SecretConfig struct {
	Host           string
	Port           string
	Path           string
	Authentication AuthenticationInfo
}

func (c SecretConfig) BuildURL() (path string) {
	if c.Path == "" {
		path = "http://" + c.Host + ":" + c.Port + "/"
	} else {
		path = "http://" + c.Host + ":" + c.Port + "/" + c.Path
	}
	return path
}

type AuthenticationInfo struct {
	AuthType  string
	AuthToken string
}

