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
	"reflect"
	"testing"

	"github.com/edgexfoundry/go-mod-secrets/pkg"
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
		return nil, pkg.ErrSecretStoreConn{}
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
	cfgHttp := SecretConfig{Host: "localhost", Port: 8080, Provider: VaultProvider}
	cfgNoop := SecretConfig{Host: "localhost", Port: 8080, Provider: "mqtt"}
	cfgInvalidCertPath := SecretConfig{Host: "localhost", Port: 8080, Provider: VaultProvider, RootCaCert: "/non-existent-directory/rootCa.crt"}

	tests := []struct {
		name      string
		cfg       SecretConfig
		expectErr bool
	}{
		{"NewSecretClient HTTP configuration", cfgHttp, false},
		{"NewSecretClient  unsupported provider", cfgNoop, true},
		{"NewSecretClient invalid CA root certificate path", cfgInvalidCertPath, true},
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
	tests := []struct {
		name           string
		keys           []string
		expectedValues map[string]string
		expectedError  error
		caller         Caller
	}{
		{
			name:           "Get Key",
			keys:           []string{"one"},
			expectedValues: map[string]string{"one": "uno"},
			expectedError:  nil,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:           "Get Keys",
			keys:           []string{"one", "two"},
			expectedValues: map[string]string{"one": "uno", "two": "dos"},
			expectedError:  nil,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:           "Get non-existent Key",
			keys:           []string{"Does not exist"},
			expectedValues: nil,
			expectedError:  pkg.NewErrSecretsNotFound([]string{"Does not exist"}),
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:           "Get all non-existent Keys",
			keys:           []string{"Does not exist", "Also does not exist"},
			expectedValues: nil,
			expectedError:  pkg.NewErrSecretsNotFound([]string{"Does not exist", "Also does not exist"}),
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:           "Get some non-existent Keys",
			keys:           []string{"one", "Does not exist", "Also does not exist"},
			expectedValues: nil,
			expectedError:  pkg.NewErrSecretsNotFound([]string{"Does not exist", "Also does not exist"}),
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:           "Handle HTTP error",
			keys:           []string{"Does not exist"},
			expectedValues: nil,
			expectedError:  pkg.NewErrSecretsNotFound([]string{"Does not exist"}),
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

			actual, err := ssm.GetValues(test.keys...)
			if test.expectedError != nil && err == nil {
				t.Errorf("Expected error but none was recieved")
			}

			if test.expectedError == nil && err != nil {
				t.Errorf("Unexpected error: %s", err.Error())
			}

			if test.expectedError != nil && !reflect.DeepEqual(err, test.expectedError) {
				t.Errorf("Observed error doesn't match expected.\nExpected: %v\nActual: %v\n", test.expectedError, err)
			}

			for k, expected := range test.expectedValues {
				if actual[k] != expected {
					t.Errorf("Expected value '%s', but got '%s'", expected, actual[k])

				}
			}
		})
	}
}
