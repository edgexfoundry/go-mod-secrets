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

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// HttpClient defines the behavior for interacting with the REST secret key/value store.
type httpClient struct {
	HttpConfig SecretConfig
	httpClient *http.Client
}

func NewSecretClient(config SecretConfig) (client SecretClient, err error) {
	switch config.Protocol {
	case HTTPProvider:
		client = httpClient{
			HttpConfig: config,
			httpClient: &http.Client{
				Timeout: time.Second * 10,
			},
		}
	default:
		err = fmt.Errorf("unsupported protocol %s provided", config.Protocol)
	}

	return
}

func (c httpClient) GetValue(key string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, c.HttpConfig.BuildURL(), nil)
	if err != nil {
		return "", err
	}

	req.Header.Set(c.HttpConfig.Authentication.AuthType, c.HttpConfig.Authentication.AuthToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", err
	}

	data, success := result["data"].(map[string]interface{})
	if !success {
		err = fmt.Errorf("no data retrieved from secrets service")
		return "", err
	}

	kv, success := data["data"].(map[string]interface{})
	if !success {
		err = fmt.Errorf("no keys retrieved from secrets service")
		return "", err
	}

	value, success := kv[key].(string)
	if !success {
		err = fmt.Errorf("no data retrieved from secrets service at key %s", key)
		return "", err
	}

	return value, nil
}

func (c httpClient) SetValue(key string, value string) error {
	outerdata := make(map[string]interface{})
	jsonData := make(map[string]string)
	jsonData[key] = value
	outerdata["data"] = jsonData

	body, err := json.Marshal(outerdata)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, c.HttpConfig.BuildURL(), bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set(c.HttpConfig.Authentication.AuthType, c.HttpConfig.Authentication.AuthToken)

	resp, err := c.httpClient.Do(req)
	if err != nil || resp == nil {
		return err
	}
	if resp.StatusCode == http.StatusBadRequest {
		return fmt.Errorf("bad request")
	}

	return nil
}

func (c httpClient) DeleteValue(key string) error {
	outerdata := make(map[string]interface{})
	jsonData := make(map[string]string)
	jsonData[key] = ""
	outerdata["data"] = jsonData

	body, err := json.Marshal(outerdata)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodDelete, c.HttpConfig.BuildURL(), bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set(c.HttpConfig.Authentication.AuthType, c.HttpConfig.Authentication.AuthToken)

	resp, err := c.httpClient.Do(req)
	if err != nil || resp == nil {
		return err
	}
	if resp.StatusCode == http.StatusBadRequest {
		return fmt.Errorf("bad request")
	}

	return nil
}
