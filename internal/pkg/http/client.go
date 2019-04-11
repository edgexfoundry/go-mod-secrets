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
package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/edgexfoundry-holding/go-mod-core-security/pkg/types"
)

type Configuration struct {
	Host           string
	Port           string
	Path           string
	Authentication types.AuthenticationInfo
}

// Client defines the behavior for interacting with the REST secret key/value store.
type Client struct {
	HttpConfig Configuration
}

var httpClient = &http.Client{
	Timeout: time.Second * 10,
}

func (c Configuration) buildURL() (path string) {
	if c.Path == "" {
		path = "http://" + c.Host + ":" + c.Port + "/"
	} else {
		path = "http://" + c.Host + ":" + c.Port + "/" + c.Path
	}
	return path
}

func (c Client) GetValue(key string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, c.HttpConfig.buildURL(), nil)
	if err != nil {
		return "", err
	}

	req.Header.Set(c.HttpConfig.Authentication.AuthType, c.HttpConfig.Authentication.AuthToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", err
	}

	data := result["data"].(map[string]interface{})
	kv := data["data"].(map[string]interface{})
	value := kv[key].(string)

	return value, nil
}

func (c Client) SetValue(data types.Payload) error {
	outerdata := make(map[string]interface{})
	jsonData := make(map[string]string)
	jsonData[data.Key] = data.Value
	outerdata["data"] = jsonData

	body, err := json.Marshal(outerdata)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, c.HttpConfig.buildURL(), bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set(c.HttpConfig.Authentication.AuthType, c.HttpConfig.Authentication.AuthToken)

	resp, err := httpClient.Do(req)
	if err != nil || resp == nil {
		return err
	}
	if resp.StatusCode == http.StatusBadRequest {
		return fmt.Errorf("bad request")
	}

	return nil
}

func (c Client) DeleteValue(key string) error {
	outerdata := make(map[string]interface{})
	jsonData := make(map[string]string)
	jsonData[key] = ""
	outerdata["data"] = jsonData

	body, err := json.Marshal(outerdata)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodDelete, c.HttpConfig.buildURL(), bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set(c.HttpConfig.Authentication.AuthType, c.HttpConfig.Authentication.AuthToken)

	resp, err := httpClient.Do(req)
	if err != nil || resp == nil {
		return err
	}
	if resp.StatusCode == http.StatusBadRequest {
		return fmt.Errorf("bad request")
	}

	return nil
}
