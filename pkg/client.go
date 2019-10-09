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

// Package pkg generalized functions, interfaces, and structs which can be used for for different data-stores
// implementations.
package pkg

type SecretClient struct {
	Manager SecretStoreManager
}

// GetSecrets returns the values requested at the provided keys.
func (sc SecretClient) GetSecrets(path string, keys ...string) (map[string]string, error) {
	secrets, err := sc.Manager.GetValues(path, keys...)
	if err != nil {
		return nil, err
	}

	return secrets, nil
}
