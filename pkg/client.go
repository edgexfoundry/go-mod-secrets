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

// Package HTTP defines the implementation specific details for a REST HTTP key store.
package pkg

import "github.com/edgexfoundry/go-mod-secrets/pkg/errors"

type SecretClient struct {
	Manager SecretStoreManager
}

func (sc SecretClient) GetSecret(key string) (string, error) {
	value, err := sc.Manager.GetValue(key)
	if err != nil {
		return "", err
	}

	if value == "" {
		return "", errors.ErrSecretNotFound{}
	}

	return value, nil
}

func (sc SecretClient) SetSecret(key string, value string) error {
	return sc.Manager.SetKeyValue(key, value)
}

func (sc SecretClient) DeleteKey(key string) error {
	_, err := sc.GetSecret(key)
	if err != nil {
		return err
	}

	return sc.Manager.DeleteKeyValue(key)
}
