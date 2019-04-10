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

// Package vault defines the implementation specific details for the Vault secret key/value store.
package vault

import "fmt"

// VaultClient defines the behavior for interacting with the Vault secret key/value store.
type Client struct {
}

func (Client) GetValue(key string) (string, error) {
	return "", fmt.Errorf("implement me")
}

func (Client) SetValue(key string) error {
	return fmt.Errorf("implement me")
}

func (Client) DeleteValue(key string) error {
	return fmt.Errorf("implement me")
}
