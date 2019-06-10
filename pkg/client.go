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

// This package defines the contract for any secret client that will interact with a secret store.
package pkg

import "github.com/edgexfoundry/go-mod-secrets/pkg/errors"

type SecretClient struct {
	Manager SecretStoreManager
}

// GetSecrets returns the values requested at the provided keys.
// If the secret manager returns a nil or empty map, a SecretNotFound error is thrown.
// If any other error is thrown by the secret manager it is bubbled up and no partial results are provided.
func (sc SecretClient) GetSecrets(keys ...string) (map[string]string, error) {
	value, err := sc.Manager.GetValues(keys...)
	if err != nil {
		return nil, err
	}

	if value == nil || len(value) == 0 {
		return nil, errors.ErrSecretNotFound{}
	}

	return value, nil
}

// SetSecrets sets the values requested at the provided keys.
// Error handling is done by the secret manager and is implementation specific.
func (sc SecretClient) SetSecrets(secrets map[string]string) error {
	return sc.Manager.SetKeyValues(secrets)
}

// DeleteSecrets deletes the provided keys and their corresponding values.
// If any error is encountered verifying the keys and values exist this function aborts and does not attempt a delete.
// Error handling for deletion is done by the secret manager and is implementation specific.
func (sc SecretClient) DeleteKeys(keys ...string) error {
	_, err := sc.GetSecrets(keys...)
	if err != nil {
		return err
	}

	return sc.Manager.DeleteKeyValues(keys...)
}
