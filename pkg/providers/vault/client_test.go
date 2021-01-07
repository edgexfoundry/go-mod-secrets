/*******************************************************************************
 * Copyright 2019 Dell Inc.
 * Copyright 2020 Intel Corp.
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
	"net/url"
	"reflect"
	"testing"

	"github.com/edgexfoundry/go-mod-secrets/pkg"
	"github.com/edgexfoundry/go-mod-secrets/pkg/types"

	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
)

var TestPath = "/data"
var TestConnError = pkg.NewErrSecretStore("testing conn error")
var TestNamespace = "database"
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
	DoCallCount int
}

func (emc *ErrorMockCaller) Do(_ *http.Request) (*http.Response, error) {
	emc.DoCallCount++
	if emc.ReturnError {
		return &http.Response{
			StatusCode: emc.StatusCode,
		}, TestConnError
	}

	return &http.Response{
		StatusCode: emc.StatusCode,
	}, nil
}

type InMemoryMockCaller struct {
	Data                 map[string]map[string]string
	Result               map[string]string
	DoCallCount          int
	nErrorsReturned      int
	NErrorsBeforeSuccess int
}

func (caller *InMemoryMockCaller) Do(req *http.Request) (*http.Response, error) {
	caller.DoCallCount++
	if caller.NErrorsBeforeSuccess != 0 {
		if caller.nErrorsReturned != caller.NErrorsBeforeSuccess {
			caller.nErrorsReturned++
			return &http.Response{
				StatusCode: 404,
			}, nil
		}
	}
	if req.Header.Get(NamespaceHeader) != TestNamespace {
		return nil, errors.New("namespace header is expected but not present in request")
	}

	switch req.Method {
	case http.MethodGet:
		if req.URL.Path != TestPath {
			return &http.Response{
				StatusCode: 404,
			}, nil
		}
		r, _ := json.Marshal(caller.Data)
		return &http.Response{
			Body:       ioutil.NopCloser(bytes.NewBufferString(string(r))),
			StatusCode: 200,
		}, nil

	case http.MethodPost:
		if req.URL.Path != TestPath {
			return &http.Response{
				StatusCode: 404,
			}, nil
		}
		var result map[string]string
		_ = json.NewDecoder(req.Body).Decode(&result)
		caller.Result = result
		return &http.Response{
			StatusCode: 200,
		}, nil
	default:
		return nil, errors.New("unsupported HTTP method")
	}
}

func TestHttpSecretStoreManager_GetValue(t *testing.T) {
	tests := []struct {
		name              string
		path              string
		keys              []string
		expectedValues    map[string]string
		expectError       bool
		expectedErrorType error
		retries           int
		expectedDoCallNum int
		caller            pkg.Caller
	}{
		{
			name:              "Get Key",
			path:              TestPath,
			keys:              []string{"one"},
			expectedValues:    map[string]string{"one": "uno"},
			expectError:       false,
			expectedErrorType: nil,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Get Keys",
			path:              TestPath,
			keys:              []string{"one", "two"},
			expectedValues:    map[string]string{"one": "uno", "two": "dos"},
			expectError:       false,
			expectedErrorType: nil,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Get all keys",
			path:              TestPath,
			keys:              nil,
			expectedValues:    map[string]string{"one": "uno", "two": "dos", "three": "tres"},
			expectError:       false,
			expectedErrorType: nil,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Get non-existent Key",
			path:              TestPath,
			keys:              []string{"Does not exist"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: pkg.NewErrSecretsNotFound([]string{"Does not exist"}),
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Get all non-existent Keys",
			path:              TestPath,
			keys:              []string{"Does not exist", "Also does not exist"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: pkg.NewErrSecretsNotFound([]string{"Does not exist", "Also does not exist"}),
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Get some non-existent Keys",
			path:              TestPath,
			keys:              []string{"one", "Does not exist", "Also does not exist"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: pkg.NewErrSecretsNotFound([]string{"Does not exist", "Also does not exist"}),
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Handle HTTP error",
			path:              TestPath,
			keys:              []string{"Does not exist"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: TestConnError,
			expectedDoCallNum: 1,
			caller: &ErrorMockCaller{
				ReturnError: true,
				StatusCode:  404,
			},
		},
		{
			name:              "Handle non-200 HTTP response",
			path:              TestPath,
			keys:              []string{"Does not exist"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: TestConnError,
			expectedDoCallNum: 1,
			caller: &ErrorMockCaller{
				ReturnError: false,
				StatusCode:  404,
			},
		},
		{
			name:              "Get Key with unknown path",
			path:              "/nonexistentpath",
			keys:              []string{"one"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: TestConnError,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "URL Error",
			path:              "bad path for URL",
			keys:              []string{"one"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: &url.Error{},
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Retry 10 times, 1st success",
			retries:           10,
			path:              TestPath,
			keys:              []string{"one"},
			expectedValues:    map[string]string{"one": "uno"},
			expectError:       false,
			expectedErrorType: nil,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Retry 9 times, all HTTP status failures",
			retries:           9,
			path:              TestPath,
			keys:              []string{"one"},
			expectedValues:    map[string]string{"one": "uno"},
			expectError:       true,
			expectedErrorType: TestConnError,
			// expected is retries + 1
			expectedDoCallNum: 10,
			caller: &ErrorMockCaller{
				ReturnError: false,
				StatusCode:  404,
			},
		},
		{
			name:              "Retry 9 times, all catastrophic failure",
			retries:           9,
			path:              TestPath,
			keys:              []string{"one"},
			expectedValues:    map[string]string{"one": "uno"},
			expectError:       true,
			expectedErrorType: TestConnError,
			expectedDoCallNum: 10,
			caller: &ErrorMockCaller{
				ReturnError: true,
			},
		},
		{
			name:              "Retry 9 times, last works",
			retries:           9,
			path:              TestPath,
			keys:              []string{"one"},
			expectedValues:    map[string]string{"one": "uno"},
			expectError:       false,
			expectedDoCallNum: 10,
			caller: &InMemoryMockCaller{
				NErrorsBeforeSuccess: 9,
				Data:                 testData,
			},
		},
		{
			name:              "Invalid retry num",
			retries:           -1,
			path:              TestPath,
			keys:              []string{"one"},
			expectedValues:    map[string]string{"one": "uno"},
			expectError:       true,
			expectedErrorType: TestConnError,
			expectedDoCallNum: 0,
			caller: &ErrorMockCaller{
				ReturnError: true,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfgHTTP := types.SecretConfig{
				Host:                    "localhost",
				Port:                    8080,
				Protocol:                "http",
				Namespace:               TestNamespace,
				AdditionalRetryAttempts: test.retries,
			}
			ssm := Client{
				HttpConfig: cfgHTTP,
				HttpCaller: test.caller,
				lc:         logger.NewMockClient(),
			}

			actual, err := ssm.GetSecrets(test.path, test.keys...)
			if test.expectedErrorType != nil && err == nil {
				t.Errorf("Expected error %v but none was received", test.expectedErrorType)
			}

			switch v := test.caller.(type) {
			case *ErrorMockCaller:
				if test.expectedDoCallNum != v.DoCallCount {
					t.Errorf("Expected %d ErrorMockCaller.Do calls, got %d", test.expectedDoCallNum, v.DoCallCount)
				}
			case *InMemoryMockCaller:
				if test.expectedDoCallNum != v.DoCallCount {
					t.Errorf("Expected %d InMemoryMockCaller.Do calls, got %d", test.expectedDoCallNum, v.DoCallCount)
				}
			}

			if !test.expectError && err != nil {
				t.Errorf("Unexpected error: %s", err.Error())
			}

			if test.expectError && test.expectedErrorType != nil {
				eet := reflect.TypeOf(test.expectedErrorType)
				aet := reflect.TypeOf(err)
				if !aet.AssignableTo(eet) {
					t.Errorf("Expected error of type %v, but got an error of type %v", eet, aet)
				}
			}

			if !test.expectError {
				for k, expected := range test.expectedValues {
					if actual[k] != expected {
						t.Errorf("Expected value '%s', but got '%s'", expected, actual[k])

					}
				}
			}
		})

	}
}

func TestHttpSecretStoreManager_SetValue(t *testing.T) {
	tests := []struct {
		name              string
		path              string
		secrets           map[string]string
		expectedValues    map[string]string
		expectError       bool
		expectedErrorType error
		retries           int
		expectedDoCallNum int
		caller            pkg.Caller
	}{
		{
			name:              "Set One Secret",
			path:              TestPath,
			secrets:           map[string]string{"one": "uno"},
			expectedValues:    map[string]string{"one": "uno"},
			expectError:       false,
			expectedErrorType: nil,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Set Multiple Secrets",
			path:              TestPath,
			secrets:           map[string]string{"one": "uno", "two": "dos"},
			expectedValues:    map[string]string{"one": "uno", "two": "dos"},
			expectError:       false,
			expectedErrorType: nil,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Handle non-200 HTTP response",
			path:              TestPath,
			secrets:           map[string]string{"": "empty"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: TestConnError,
			expectedDoCallNum: 1,
			caller: &ErrorMockCaller{
				ReturnError: false,
				StatusCode:  404,
			},
		},
		{
			name:              "Set One Secret with unknown path",
			path:              "/nonexistentpath",
			secrets:           map[string]string{"one": "uno"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: TestConnError,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "URL Error",
			path:              "bad path for URL",
			secrets:           map[string]string{"one": "uno"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: &url.Error{},
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Retry 10 times, 1st success",
			retries:           10,
			path:              TestPath,
			secrets:           map[string]string{"one": "uno"},
			expectedValues:    map[string]string{"one": "uno"},
			expectError:       false,
			expectedErrorType: nil,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Retry 9 times, all HTTP status failures",
			retries:           9,
			path:              TestPath,
			secrets:           map[string]string{"one": "uno"},
			expectedValues:    map[string]string{"one": "uno"},
			expectError:       true,
			expectedErrorType: TestConnError,
			// expected is retries + 1
			expectedDoCallNum: 10,
			caller: &ErrorMockCaller{
				ReturnError: false,
				StatusCode:  404,
			},
		},
		{
			name:              "Retry 9 times, all catastrophic failure",
			retries:           9,
			path:              TestPath,
			secrets:           map[string]string{"one": "uno"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: TestConnError,
			expectedDoCallNum: 10,
			caller: &ErrorMockCaller{
				ReturnError: true,
			},
		},
		{
			name:              "Retry 9 times, last works",
			retries:           9,
			path:              TestPath,
			secrets:           map[string]string{"one": "uno"},
			expectedValues:    map[string]string{"one": "uno"},
			expectError:       false,
			expectedDoCallNum: 10,
			caller: &InMemoryMockCaller{
				NErrorsBeforeSuccess: 9,
				Data:                 testData,
			},
		},
		{
			name:              "Invalid retry num",
			retries:           -1,
			path:              TestPath,
			secrets:           map[string]string{"one": "uno"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: TestConnError,
			expectedDoCallNum: 0,
			caller: &ErrorMockCaller{
				ReturnError: true,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfgHTTP := types.SecretConfig{
				Host:                    "localhost",
				Port:                    8080,
				Protocol:                "http",
				Namespace:               TestNamespace,
				AdditionalRetryAttempts: test.retries,
			}
			ssm := Client{
				HttpConfig: cfgHTTP,
				HttpCaller: test.caller,
				lc:         logger.NewMockClient(),
			}

			err := ssm.StoreSecrets(test.path, test.secrets)
			if test.expectedErrorType != nil && err == nil {
				t.Errorf("Expected error %v but none was received", test.expectedErrorType)
			}

			switch v := test.caller.(type) {
			case *ErrorMockCaller:
				if test.expectedDoCallNum != v.DoCallCount {
					t.Errorf("Expected %d ErrorMockCaller.Do calls, got %d", test.expectedDoCallNum, v.DoCallCount)
				}
			case *InMemoryMockCaller:
				if test.expectedDoCallNum != v.DoCallCount {
					t.Errorf("Expected %d InMemoryMockCaller.Do calls, got %d", test.expectedDoCallNum, v.DoCallCount)
				}
			}

			if !test.expectError && err != nil {
				t.Errorf("Unexpected error: %s", err.Error())
			}

			if test.expectError && test.expectedErrorType != nil && err != nil {
				eet := reflect.TypeOf(test.expectedErrorType)
				aet := reflect.TypeOf(err)
				if !aet.AssignableTo(eet) {
					t.Errorf("Expected error of type %v, but got an error of type %v", eet, aet)
				}
			}

			if !test.expectError && test.secrets != nil {
				keys := make([]string, 0, len(test.secrets))
				for k := range test.secrets {
					keys = append(keys, k)
				}
				actual, _ := ssm.GetSecrets(test.path, keys...)
				for k, expected := range test.expectedValues {
					if actual[k] != expected {
						t.Errorf("After storing secrets, expected value '%s', but got '%s'", expected, actual[k])

					}
				}
			}
		})
	}
}
