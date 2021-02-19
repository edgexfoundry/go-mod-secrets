/*******************************************************************************
 * Copyright 2019 Dell Inc.
 * Copyright 2021 Intel Corp.
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
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edgexfoundry/go-mod-secrets/v2/pkg"
	"github.com/edgexfoundry/go-mod-secrets/v2/pkg/types"

	"github.com/edgexfoundry/go-mod-core-contracts/v2/clients/logger"
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

func TestNewSecretsClient(t *testing.T) {
	authToken := "testToken"
	var tokenDataMap sync.Map
	tokenDataMap.Store(authToken, types.TokenMetadata{
		Renewable: true,
		Ttl:       10000,
		Period:    10000,
	})
	server := GetMockTokenServer(&tokenDataMap)
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	host, port, _ := net.SplitHostPort(serverURL.Host)
	portNum, _ := strconv.Atoi(port)

	cfgHTTP := types.SecretConfig{Protocol: "http", Host: host, Port: portNum, Authentication: types.AuthenticationInfo{AuthToken: authToken}}
	cfgInvalidCertPath := types.SecretConfig{Protocol: "https", Host: host, Port: portNum, RootCaCertPath: "/non-existent-directory/rootCa.crt", Authentication: types.AuthenticationInfo{AuthToken: authToken}}
	cfgNamespace := types.SecretConfig{Protocol: "http", Host: host, Port: portNum, Namespace: "database", Authentication: types.AuthenticationInfo{AuthToken: authToken}}
	cfgInvalidTime := types.SecretConfig{Protocol: "http", Host: host, Port: portNum, RetryWaitPeriod: "not a real time spec", Authentication: types.AuthenticationInfo{AuthToken: authToken}}
	cfgValidTime := types.SecretConfig{Protocol: "http", Host: host, Port: portNum, RetryWaitPeriod: "1s", Authentication: types.AuthenticationInfo{AuthToken: authToken}}
	cfgEmptyToken := types.SecretConfig{Protocol: "http", Host: host, Port: portNum, RetryWaitPeriod: "1s"}
	s := time.Second
	bkgCtx := context.Background()

	tests := []struct {
		name         string
		cfg          types.SecretConfig
		expectErr    bool
		expectedTime *time.Duration
	}{
		{"NewSecretClient HTTP configuration", cfgHTTP, false, nil},
		{"NewSecretClient invalid CA root certificate path", cfgInvalidCertPath, true, nil},
		{"NewSecretClient with Namespace", cfgNamespace, false, nil},
		{"NewSecretClient with invalid RetryWaitPeriod", cfgInvalidTime, true, nil},
		{"NewSecretClient with valid RetryWaitPeriod", cfgValidTime, false, &s},
		{"NewSecretClient with empty token", cfgEmptyToken, true, nil},
	}
	mockLogger := logger.NewMockClient()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			emptyTokenCallbackFunc := func(expiredToken string) (replacementToken string, retry bool) {
				return "", false
			}
			client, err := NewSecretsClient(bkgCtx, test.cfg, mockLogger, emptyTokenCallbackFunc)
			if test.expectErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			if test.expectedTime != nil {
				assert.Equal(t, *test.expectedTime, client.Config.RetryWaitPeriodTime)
			}
		})
	}
}

func TestMultipleTokenRenewals(t *testing.T) {
	// run in parallel with other tests
	t.Parallel()
	// setup
	tokenPeriod := 6
	var tokenDataMap sync.Map
	// ttl > half of period
	tokenDataMap.Store("testToken1", types.TokenMetadata{
		Renewable: true,
		Ttl:       tokenPeriod * 7 / 10,
		Period:    tokenPeriod,
	})
	// ttl = half of period
	tokenDataMap.Store("testToken2", types.TokenMetadata{
		Renewable: true,
		Ttl:       tokenPeriod / 2,
		Period:    tokenPeriod,
	})
	// ttl < half of period
	tokenDataMap.Store("testToken3", types.TokenMetadata{
		Renewable: true,
		Ttl:       tokenPeriod * 3 / 10,
		Period:    tokenPeriod,
	})
	// to be expired token
	tokenDataMap.Store("toToExpiredToken", types.TokenMetadata{
		Renewable: true,
		Ttl:       1,
		Period:    tokenPeriod,
	})
	// expired token
	tokenDataMap.Store("expiredToken", types.TokenMetadata{
		Renewable: true,
		Ttl:       0,
		Period:    tokenPeriod,
	})
	// not renewable token
	tokenDataMap.Store("unrenewableToken", types.TokenMetadata{
		Renewable: false,
		Ttl:       0,
		Period:    tokenPeriod,
	})

	server := GetMockTokenServer(&tokenDataMap)
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoErrorf(t, err, "error on parsing server url %s: %s", server.URL, err)

	host, port, _ := net.SplitHostPort(serverURL.Host)
	portNum, _ := strconv.Atoi(port)

	bkgCtx := context.Background()

	mockLogger := logger.NewMockClient()
	tests := []struct {
		name                     string
		authToken                string
		retries                  int
		tokenExpiredCallbackFunc pkg.TokenExpiredCallback
		expectError              bool
		expectedErrorType        error
	}{
		{
			name:              "New secret client with testToken1, more than half of TTL remaining",
			authToken:         "testToken1",
			expectError:       false,
			expectedErrorType: nil,
		},
		{
			name:              "New secret client with the same first token again",
			authToken:         "testToken1",
			expectError:       false,
			expectedErrorType: nil,
		},
		{
			name:              "New secret client with testToken2, half of TTL remaining",
			authToken:         "testToken2",
			expectError:       false,
			expectedErrorType: nil,
		},
		{
			name:              "New secret client with testToken3, less than half of TTL remaining",
			authToken:         "testToken3",
			expectError:       false,
			expectedErrorType: nil,
		},
		{
			name:              "New secret client with expired token, no TTL remaining",
			authToken:         "expiredToken",
			expectError:       true,
			expectedErrorType: ErrHTTPResponse{StatusCode: 403, ErrMsg: "forbidden"},
		},
		{
			name:              "New secret client with expired token, no TTL remaining, 3 retries",
			authToken:         "expiredToken",
			retries:           3,
			expectError:       true,
			expectedErrorType: ErrHTTPResponse{StatusCode: 403, ErrMsg: "forbidden"},
		},
		{
			name:              "New secret client with unauthenticated token",
			authToken:         "invalidToken",
			expectError:       true,
			expectedErrorType: ErrHTTPResponse{StatusCode: 403, ErrMsg: "forbidden"},
		},
		{
			name:              "New secret client with unrenewable token",
			authToken:         "unrenewableToken",
			expectError:       false,
			expectedErrorType: nil,
		},
		{
			name:      "New secret client with to be expired token, 3 retries, retry func",
			authToken: "toToExpiredToken",
			retries:   3,
			tokenExpiredCallbackFunc: func(expiredToken string) (replacementToken string, retry bool) {
				time.Sleep(1 * time.Second)
				return "testToken1", true
			},
			expectError:       false,
			expectedErrorType: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfgHTTP := types.SecretConfig{
				Host:                    host,
				Port:                    portNum,
				Protocol:                "http",
				Authentication:          types.AuthenticationInfo{AuthToken: test.authToken},
				AdditionalRetryAttempts: test.retries,
			}

			client, err := NewSecretsClient(bkgCtx, cfgHTTP, mockLogger, test.tokenExpiredCallbackFunc)

			if test.expectError {
				require.Errorf(t, err, "Expected error %v but none was received", test.expectedErrorType)
				if test.expectedErrorType != nil {
					eet := reflect.TypeOf(test.expectedErrorType)
					et := reflect.TypeOf(err)
					require.Truef(t, et.AssignableTo(eet), "Expected error of type %v, but got an error of type %v", eet, et)
				}
				return
			}

			require.NoError(t, err)

			// look up the token data again after renewal
			lookupTokenData, err := client.getTokenDetails()
			require.NoError(t, err)

			if lookupTokenData != nil && lookupTokenData.Renewable &&
				lookupTokenData.Ttl < tokenPeriod/2 {
				tokenData, _ := tokenDataMap.Load(test.authToken)
				tokenTTL := tokenData.(types.TokenMetadata).Ttl
				t.Errorf("failed to renew token with the token period %d: the current TTL %d and the old TTL: %d",
					tokenPeriod, lookupTokenData.Ttl, tokenTTL)
			}
		})
	}
	// wait for some time to allow renewToken to be run if any
	time.Sleep(7 * time.Second)
}

func TestMultipleClientsFailureCase(t *testing.T) {
	// run in parallel with other tests
	t.Parallel()
	// setup
	tokenPeriod := 6
	var tokenDataMap sync.Map

	// expired token
	tokenDataMap.Store("expiredToken", types.TokenMetadata{
		Renewable: true,
		Ttl:       0,
		Period:    tokenPeriod,
	})

	server := GetMockTokenServer(&tokenDataMap)
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	host, port, _ := net.SplitHostPort(serverURL.Host)
	portNum, _ := strconv.Atoi(port)

	bkgCtx := context.Background()

	mockLogger := logger.NewMockClient()
	cfgHTTP := types.SecretConfig{
		Host:           host,
		Port:           portNum,
		Protocol:       "http",
		Authentication: types.AuthenticationInfo{AuthToken: "expiredToken"},
	}

	emptyTokenCallbackFunc := func(expiredToken string) (replacementToken string, retry bool) {
		return "", false
	}
	_, err = NewSecretsClient(bkgCtx, cfgHTTP, mockLogger, emptyTokenCallbackFunc)
	// it will fail since the token is expired
	assert.Error(t, err)

	// create a second secret client with the same expired token
	_, err = NewSecretsClient(bkgCtx, cfgHTTP, mockLogger, emptyTokenCallbackFunc)
	assert.Error(t, err)

	// wait for some time to allow renewToken to be run if any
	time.Sleep(2 * time.Second)
}

func TestConcurrentSecretClientTokenRenewals(t *testing.T) {
	// run in parallel with other tests
	t.Parallel()
	// setup
	tokenPeriod := 6
	var tokenDataMap sync.Map

	// ttl < half of period
	tokenDataMap.Store("testToken3", types.TokenMetadata{
		Renewable: true,
		Ttl:       tokenPeriod * 3 / 10,
		Period:    tokenPeriod,
	})

	server := GetMockTokenServer(&tokenDataMap)
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	host, port, _ := net.SplitHostPort(serverURL.Host)
	portNum, _ := strconv.Atoi(port)

	bkgCtx := context.Background()
	mockLogger := logger.NewMockClient()
	cfgHTTP := types.SecretConfig{
		Host:           host,
		Port:           portNum,
		Protocol:       "http",
		Authentication: types.AuthenticationInfo{AuthToken: "testToken3"},
	}

	// number of clients to be created to run in go-routines
	numOfClients := 100
	for i := 0; i < numOfClients; i++ {
		go func(ith int) {
			emptyTokenCallbackFunc := func(expiredToken string) (replacementToken string, retry bool) {
				return "", false
			}
			_, err = NewSecretsClient(bkgCtx, cfgHTTP, mockLogger, emptyTokenCallbackFunc)
			require.NoError(t, err)
			time.Sleep(1 * time.Second)
		}(i)
	}

	// wait for some time to allow renewToken to be run if any
	time.Sleep(2 * time.Second)
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
			expectedErrorType: nil,
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
				Config:     cfgHTTP,
				HttpCaller: test.caller,
				lc:         logger.NewMockClient(),
			}

			actual, err := ssm.GetSecrets(test.path, test.keys...)
			if test.expectError {
				require.Error(t, err)

				if test.expectedErrorType != nil {
					eet := reflect.TypeOf(test.expectedErrorType)
					aet := reflect.TypeOf(err)
					if !aet.AssignableTo(eet) {
						t.Errorf("Expected error of type %v, but got an error of type %v", eet, aet)
					}
				}

				return
			}

			var mockType string
			var callCount int
			switch v := test.caller.(type) {
			case *ErrorMockCaller:
				mockType = "ErrorMockCaller"
				callCount = v.DoCallCount
			case *InMemoryMockCaller:
				mockType = "InMemoryMockCaller"
				callCount = v.DoCallCount
			}

			require.Equalf(t, test.expectedDoCallNum, callCount,
				"Expected %d %s.Do calls, got %d", mockType, test.expectedDoCallNum, callCount)

			for k, expected := range test.expectedValues {
				if actual[k] != expected {
					assert.Equalf(t, expected, actual[k], "Expected value '%s', but got '%s'", expected, actual[k])
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
			expectedErrorType: nil,
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
				Config:     cfgHTTP,
				HttpCaller: test.caller,
				lc:         logger.NewMockClient(),
			}

			err := ssm.StoreSecrets(test.path, test.secrets)

			if test.expectError {
				require.Error(t, err)

				if test.expectedErrorType != nil {
					eet := reflect.TypeOf(test.expectedErrorType)
					aet := reflect.TypeOf(err)
					if !aet.AssignableTo(eet) {
						t.Errorf("Expected error of type %v, but got an error of type %v", eet, aet)
					}
				}

				return
			}

			var mockType string
			var callCount int
			switch v := test.caller.(type) {
			case *ErrorMockCaller:
				mockType = "ErrorMockCaller"
				callCount = v.DoCallCount
			case *InMemoryMockCaller:
				mockType = "InMemoryMockCaller"
				callCount = v.DoCallCount
			}

			require.Equalf(t, test.expectedDoCallNum, callCount,
				"Expected %d %s.Do calls, got %d", mockType, test.expectedDoCallNum, callCount)

			keys := make([]string, 0, len(test.secrets))
			for k := range test.secrets {
				keys = append(keys, k)
			}

			actual, _ := ssm.GetSecrets(test.path, keys...)
			for k, expected := range test.expectedValues {
				assert.Equalf(t, expected, actual[k],
					"After storing secrets, expected value '%s', but got '%s'", expected, actual[k])
			}
		})
	}
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
