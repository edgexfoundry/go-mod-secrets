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
package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/edgexfoundry/go-mod-secrets/pkg"
	"github.com/edgexfoundry/go-mod-secrets/pkg/errors"
)

// HttpSecretStoreManager defines the behavior for interacting with the REST secret key/value store.
type HttpSecretStoreManager struct {
	HttpConfig SecretConfig
	HttpCaller Caller
}

// Constructs a SecretClient which communicates with a storage mechanism via HTTP
func NewSecretClient(config SecretConfig) (client pkg.SecretClient, err error) {
	switch config.Provider {
	case HTTPProvider:
		client = pkg.SecretClient{
			Manager: HttpSecretStoreManager{
				HttpConfig: config,
				HttpCaller: http.DefaultClient,
			},
		}
		return client, nil
	default:
		err = fmt.Errorf("unsupported provider %s provided", config.Protocol)
	}

	return
}

func (c HttpSecretStoreManager) GetValues(keys ...string) (map[string]string, error) {
	data, err := c.getAllKeys()
	if err != nil {
		return nil, err
	}

	values := make(map[string]string)

	for _, key := range keys {
		value, success := data[key].(string)
		if !success {
			return nil, errors.ErrSecretNotFound{Key: key}
		}

		values[key] = value
	}

	return values, nil
}

func (c HttpSecretStoreManager) SetKeyValues(secrets map[string]string) error {
	body, err := json.Marshal(secrets)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, c.HttpConfig.BuildURL(), bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set(c.HttpConfig.Authentication.AuthType, c.HttpConfig.Authentication.AuthToken)
	resp, err := c.HttpCaller.Do(req)
	if err != nil || resp == nil {
		return err
	}
	if resp.StatusCode == http.StatusBadRequest {
		return fmt.Errorf("bad request")
	}

	return nil
}

func (c HttpSecretStoreManager) DeleteKeyValues(keys ...string) error {
	data, err := c.getAllKeys()
	if err != nil {
		return err
	}

	for _, key := range keys {
		_, present := data[key]
		if !present {
			return errors.ErrSecretNotFound{
				Key: key,
			}
		}
		delete(data, key)
	}

	body, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, c.HttpConfig.BuildURL(), bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set(c.HttpConfig.Authentication.AuthType, c.HttpConfig.Authentication.AuthToken)
	resp, err := c.HttpCaller.Do(req)
	if err != nil || resp == nil {
		return err
	}
	if resp.StatusCode == http.StatusBadRequest {
		return fmt.Errorf("bad request")
	}

	return nil
}

func (c HttpSecretStoreManager) getAllKeys() (map[string]interface{}, error) {
	req, err := http.NewRequest(http.MethodGet, c.HttpConfig.BuildURL(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set(c.HttpConfig.Authentication.AuthType, c.HttpConfig.Authentication.AuthToken)
	resp, err := c.HttpCaller.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	data, success := result["data"].(map[string]interface{})
	if !success {
		err = fmt.Errorf("no data retrieved from secrets service")
		return nil, err
	}

	return data, nil
}
