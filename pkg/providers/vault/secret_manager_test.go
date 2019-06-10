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
	"errors"
	"io/ioutil"
	"net/http"
	"testing"
)

var cfgHttp = SecretConfig{Host: "localhost", Port: 8080, Protocol: "http"}
var testData = map[string]map[string]string{
	"data": {
		"one":   "uno",
		"two":   "dos",
		"three": "tres",
	},
}

type ErrorMockCaller struct {
	StatusCode  int
	ReturnError bool
}

func (emc ErrorMockCaller) Do(req *http.Request) (*http.Response, error) {
	if emc.ReturnError {
		return nil, errors.New("returning error from mock client")
	}

	return &http.Response{
		StatusCode: 200,
	}, nil
}

type InMemoryMockCaller struct {
	Data   map[string]map[string]string
	Result map[string]string
}

func (immc *InMemoryMockCaller) Do(req *http.Request) (*http.Response, error) {
	switch req.Method {
	case http.MethodGet:
		r, _ := json.Marshal(immc.Data)
		return &http.Response{
			Body:       ioutil.NopCloser(bytes.NewBufferString(string(r))),
			StatusCode: 200,
		}, nil

	case http.MethodPost:

		var result map[string]string
		_ = json.NewDecoder(req.Body).Decode(&result)
		immc.Result = result
		return &http.Response{
			StatusCode: 200,
		}, nil
	default:
		return nil, errors.New("unsupported HTTP method")
	}
}

func TestNewSecretClient(t *testing.T) {
	cfgHttp := SecretConfig{Host: "localhost", Port: 8080, Provider: HTTPProvider}
	cfgNoop := SecretConfig{Host: "localhost", Port: 8080, Provider: "mqtt"}

	tests := []struct {
		name      string
		cfg       SecretConfig
		expectErr bool
	}{
		{"newHttp", cfgHttp, false},
		{"newNoop", cfgNoop, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSecretClient(tt.cfg)
			if err != nil {
				if !tt.expectErr {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if tt.expectErr {
					t.Errorf("did not receive expected error: %s", tt.name)
				}
			}
		})
	}
}

func TestHttpSecretStoreManager_GetValue(t *testing.T) {
	ssm := HttpSecretStoreManager{
		HttpConfig: cfgHttp,
		HttpCaller: &InMemoryMockCaller{
			Data: testData,
		}}

	v, err := ssm.GetValues("one")
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}

	if v["one"] != "uno" {
		t.Errorf("Expected value '%s', but got '%s'", "uno", v)
	}
}

func TestHttpSecretStoreManager_GetValue2(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		expectedValue string
		expectError   bool
		caller        Caller
	}{
		{
			name:          "Get Key",
			key:           "one",
			expectedValue: "uno",
			expectError:   false,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:          "Get non-existent Key",
			key:           "Does not exist",
			expectedValue: "",
			expectError:   true,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:          "Handle HTTP error",
			key:           "Does not exist",
			expectedValue: "",
			expectError:   true,
			caller: ErrorMockCaller{
				StatusCode: 404,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ssm := HttpSecretStoreManager{
				HttpConfig: cfgHttp,
				HttpCaller: &InMemoryMockCaller{
					Data: testData,
				}}

			v, err := ssm.GetValues(test.key)
			if test.expectError && err == nil {
				t.Errorf("Expected error but none was recieved")
			}

			if !test.expectError && err != nil {
				t.Errorf("Unexpected error: %s", err.Error())
			}

			if v[test.key] != test.expectedValue {
				t.Errorf("Expected value '%s', but got '%s'", test.expectedValue, v)
			}
		})
	}
}

func TestHttpSecretStoreManager_SetValue(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		value       string
		expectError bool
		caller      Caller
	}{
		{
			name:        "Set Key",
			key:         "four",
			value:       "cuatro",
			expectError: false,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:        "Overwrite existing key",
			key:         "dos",
			value:       "dos",
			expectError: false,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:        "Set key error handling",
			key:         "four",
			value:       "cuatro",
			expectError: false,
			caller: &ErrorMockCaller{
				StatusCode: 500,
			},
		},
	}
	for _, test := range tests {
		immc := &InMemoryMockCaller{
			Data: testData,
		}

		t.Run(test.name, func(t *testing.T) {
			ssm := HttpSecretStoreManager{
				HttpConfig: cfgHttp,
				HttpCaller: immc}

			err := ssm.SetKeyValues(map[string]string{test.key: test.value})
			if test.expectError && err == nil {
				t.Errorf("Expected error but none was recieved")
			}

			if !test.expectError && err != nil {
				t.Errorf("Unexpected error: %s", err.Error())
			}
			actualValue := immc.Result[test.key]
			if actualValue != test.value {
				t.Errorf("Expected value of '%s' , but got '%s'", test.value, actualValue)
			}

		})
	}
}

func TestHttpSecretStoreManager_SetDelete(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		value       string
		expectError bool
		caller      Caller
	}{
		{
			name:        "Delete Key",
			key:         "one",
			expectError: false,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:        "Delete Non-existent Key",
			key:         "Does not exist",
			expectError: true,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
	}
	for _, test := range tests {
		immc := &InMemoryMockCaller{
			Data: testData,
		}

		t.Run(test.name, func(t *testing.T) {
			ssm := HttpSecretStoreManager{
				HttpConfig: cfgHttp,
				HttpCaller: immc}

			err := ssm.DeleteKeyValues(test.key)
			if test.expectError && err == nil {
				t.Errorf("Expected error but none was recieved")
			}

			if !test.expectError && err != nil {
				t.Errorf("Unexpected error: %s", err.Error())
			}
			_, ok := immc.Result[test.key]
			if ok {
				t.Error("Expected key to be deleted")
			}
		})
	}
}
