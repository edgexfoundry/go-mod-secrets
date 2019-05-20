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

// Package interfaces defines the contracts that must be implemented by services.
package pkg

// SecretClient is an interface defining the basic operations for interacting with a secrets store
type SecretClient interface {

	// GetValue returns a value for the supplied key from the secrets store
	GetValue(key string) (string, error)

	// SetValue will persist a given key/value pair in the secrets store
	SetValue(key string, value string) error

	// DeleteValue will remove a key and its associated value from the secrets store
	DeleteValue(key string) error
}
