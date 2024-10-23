/*******************************************************************************
 * Copyright 2019 Dell Inc.
 * Copyright 2021 Intel Corp.
 * Copyright 2024 IOTech Ltd
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

package openbao

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edgexfoundry/go-mod-secrets/v4/pkg"
	"github.com/edgexfoundry/go-mod-secrets/v4/pkg/types"

	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"
)

const (
	// define as constants to avoid using global variables as global variables are evil to the whole package level scope:
	// Global variables can cause side effects which are difficult to keep track of. A code in one function may
	// change the variables state while another unrelated chunk of code may be affected by it.
	testName      = "secret1"
	testName2     = "secret2"
	testName3     = "secret3"
	testName4     = "secret4"
	testNamespace = "database"
)

func TestNewSecretsClient(t *testing.T) {
	authToken := "testToken"
	var tokenDataMap sync.Map
	tokenDataMap.Store(authToken, TokenLookupResponse{
		Data: types.TokenMetadata{
			Renewable: true,
			Ttl:       10000,
			Period:    10000,
		},
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
	cfgEmptyToken := types.SecretConfig{Protocol: "http", Host: host, Port: portNum}
	bkgCtx := context.Background()

	tests := []struct {
		name      string
		cfg       types.SecretConfig
		expectErr bool
	}{
		{"NewSecretClient HTTP configuration", cfgHTTP, false},
		{"NewSecretClient invalid CA root certificate path", cfgInvalidCertPath, true},
		{"NewSecretClient with Namespace", cfgNamespace, false},
		{"NewSecretClient with empty token", cfgEmptyToken, true},
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
			require.NotNil(t, client)
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
	tokenDataMap.Store("testToken1", TokenLookupResponse{
		Data: types.TokenMetadata{
			Renewable: true,
			Ttl:       tokenPeriod * 7 / 10,
			Period:    tokenPeriod,
		},
	})
	// ttl = half of period
	tokenDataMap.Store("testToken2", TokenLookupResponse{
		Data: types.TokenMetadata{
			Renewable: true,
			Ttl:       tokenPeriod / 2,
			Period:    tokenPeriod,
		},
	})
	// ttl < half of period
	tokenDataMap.Store("testToken3", TokenLookupResponse{
		Data: types.TokenMetadata{
			Renewable: true,
			Ttl:       tokenPeriod * 3 / 10,
			Period:    tokenPeriod,
		},
	})
	// to be expired token
	tokenDataMap.Store("toToExpiredToken", TokenLookupResponse{
		Data: types.TokenMetadata{
			Renewable: true,
			Ttl:       1,
			Period:    tokenPeriod,
		},
	})
	// expired token
	tokenDataMap.Store("expiredToken", TokenLookupResponse{
		Data: types.TokenMetadata{
			Renewable: true,
			Ttl:       0,
			Period:    tokenPeriod,
		},
	})
	// not renewable token
	tokenDataMap.Store("unrenewableToken", TokenLookupResponse{
		Data: types.TokenMetadata{
			Renewable: false,
			Ttl:       0,
			Period:    tokenPeriod,
		},
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
			name:              "New secret client with expired token, no TTL remaining",
			authToken:         "expiredToken",
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
			name:      "New secret client with to be expired token, and retry func",
			authToken: "toToExpiredToken",
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
				Host:           host,
				Port:           portNum,
				Protocol:       "http",
				Authentication: types.AuthenticationInfo{AuthToken: test.authToken},
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
				tokenTTL := tokenData.(TokenLookupResponse).Data.Ttl
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
	tokenDataMap.Store("expiredToken", TokenLookupResponse{
		Data: types.TokenMetadata{
			Renewable: true,
			Ttl:       0,
			Period:    tokenPeriod,
		},
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
	tokenDataMap.Store("testToken3", TokenLookupResponse{
		Data: types.TokenMetadata{
			Renewable: true,
			Ttl:       tokenPeriod * 3 / 10,
			Period:    tokenPeriod,
		},
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
		go func() {
			emptyTokenCallbackFunc := func(expiredToken string) (replacementToken string, retry bool) {
				return "", false
			}
			// use local version of err to avoid data race condition on err from func closure
			// i.e., local version is thread-safe
			client, err := NewSecretsClient(bkgCtx, cfgHTTP, mockLogger, emptyTokenCallbackFunc)
			require.NoError(t, err)
			require.NotNil(t, client)
		}()
	}

	// wait for some time to allow renewToken to be run if any
	time.Sleep(2 * time.Second)
}

func TestHttpSecretStoreManager_GetSecret(t *testing.T) {
	TestConnError := pkg.NewErrSecretStore("testing conn error")
	TestConnErrorSecretNameNotFound := pkg.NewErrSecretNameNotFound("testing secretName error")
	testData := getTestSecretsData()
	tests := []struct {
		name              string
		secretName        string
		keys              []string
		expectedValues    map[string]string
		expectedErrorType error
		expectedDoCallNum int
		caller            pkg.Caller
	}{
		{
			name:              "Get Key",
			secretName:        testName,
			keys:              []string{"one"},
			expectedValues:    map[string]string{"one": "uno"},
			expectedErrorType: nil,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Get Two Keys",
			secretName:        testName,
			keys:              []string{"one", "two"},
			expectedValues:    map[string]string{"one": "uno", "two": "dos"},
			expectedErrorType: nil,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Get all keys",
			secretName:        testName,
			keys:              nil,
			expectedValues:    map[string]string{"one": "uno", "two": "dos", "three": "tres"},
			expectedErrorType: nil,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Get non-existent Key",
			secretName:        testName,
			keys:              []string{"Does not exist"},
			expectedValues:    nil,
			expectedErrorType: pkg.NewErrSecretsNotFound([]string{"Does not exist"}),
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Get all non-existent Keys",
			secretName:        testName,
			keys:              []string{"Does not exist", "Also does not exist"},
			expectedValues:    nil,
			expectedErrorType: pkg.NewErrSecretsNotFound([]string{"Does not exist", "Also does not exist"}),
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Get some non-existent Keys",
			secretName:        testName,
			keys:              []string{"one", "Does not exist", "Also does not exist"},
			expectedValues:    nil,
			expectedErrorType: pkg.NewErrSecretsNotFound([]string{"Does not exist", "Also does not exist"}),
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Handle HTTP no secretName error",
			secretName:        testName,
			keys:              []string{"Does not exist"},
			expectedValues:    nil,
			expectedErrorType: TestConnErrorSecretNameNotFound,
			expectedDoCallNum: 1,
			caller: &ErrorMockCaller{
				ReturnError: false,
				StatusCode:  404,
				ErrorType:   pkg.NewErrSecretNameNotFound("Not found"),
			},
		},
		{
			name:              "Handle non-200 HTTP response",
			secretName:        testName,
			keys:              []string{"Does not exist"},
			expectedValues:    nil,
			expectedErrorType: TestConnError,
			expectedDoCallNum: 1,
			caller: &ErrorMockCaller{
				ReturnError: false,
				StatusCode:  400,
				ErrorType:   pkg.NewErrSecretStore("Error"),
			},
		},
		{
			name:              "Get Key with unknown secretName",
			secretName:        "nonexistentSecretName",
			keys:              []string{"one"},
			expectedValues:    nil,
			expectedErrorType: TestConnErrorSecretNameNotFound,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfgHTTP := types.SecretConfig{
				Host:      "localhost",
				Port:      8080,
				Protocol:  "http",
				Namespace: testNamespace,
				BasePath:  "test-service",
			}
			ssm := Client{
				Config:     cfgHTTP,
				HttpCaller: test.caller,
				lc:         logger.NewMockClient(),
			}

			actual, err := ssm.GetSecret(test.secretName, test.keys...)
			if test.expectedErrorType != nil {
				require.Error(t, err)

				eet := reflect.TypeOf(test.expectedErrorType)
				aet := reflect.TypeOf(err)
				if !aet.AssignableTo(eet) {
					t.Errorf("Expected error of type %v, but got an error of type %v", eet, aet)
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

func TestHttpSecretStoreManager_StoreSecret(t *testing.T) {
	TestConnError := pkg.NewErrSecretStore("testing conn error")
	testData := getTestSecretsData()
	tests := []struct {
		name              string
		secretName        string
		secrets           map[string]string
		expectedValues    map[string]string
		expectError       bool
		expectedErrorType error
		expectedDoCallNum int
		caller            pkg.Caller
	}{
		{
			name:              "Set One Secret",
			secretName:        testName,
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
			secretName:        testName,
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
			secretName:        testName,
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
			name:              "Set One Secret with unknown secretName",
			secretName:        "nonexistentSecretName",
			secrets:           map[string]string{"one": "uno"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: TestConnError,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfgHTTP := types.SecretConfig{
				Host:      "localhost",
				Port:      8080,
				Protocol:  "http",
				Namespace: testNamespace,
				BasePath:  "test-service",
			}
			ssm := Client{
				Config:     cfgHTTP,
				HttpCaller: test.caller,
				lc:         logger.NewMockClient(),
			}

			err := ssm.StoreSecret(test.secretName, test.secrets)

			if test.expectError {
				require.Error(t, err)

				eet := reflect.TypeOf(test.expectedErrorType)
				aet := reflect.TypeOf(err)
				if !aet.AssignableTo(eet) {
					t.Errorf("Expected error of type %v, but got an error of type %v", eet, aet)
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

			actual, err := ssm.GetSecret(test.secretName, keys...)
			require.NoError(t, err)
			for k, expected := range test.expectedValues {
				assert.Equalf(t, expected, actual[k],
					"After storing secrets, expected value '%s', but got '%s'", expected, actual[k])
			}
		})
	}
}

type SimpleMockAuthHttpCaller struct {
	authTokenHeader string
	authToken       string
	statusCode      int
	returnError     bool
	returnResponse  string
}

func (smhc *SimpleMockAuthHttpCaller) Do(req *http.Request) (*http.Response, error) {
	switch req.Method {
	case http.MethodGet, http.MethodPost:
		if smhc.returnError {
			return &http.Response{
				StatusCode: smhc.statusCode,
			}, pkg.NewErrSecretStore("http response error")
		}

		if req.Header.Get(smhc.authTokenHeader) != smhc.authToken {
			return nil, fmt.Errorf("auth header %s is expected but not present in request", smhc.authTokenHeader)
		}

		return &http.Response{
			StatusCode: smhc.statusCode,
			Body:       io.NopCloser(bytes.NewBufferString(smhc.returnResponse)),
		}, nil

	default:
		return nil, errors.New("unsupported HTTP method")
	}
}

func getTestSecretsData() map[string]map[string]string {
	return map[string]map[string]string{
		"data": {
			"one":   "uno",
			"two":   "dos",
			"three": "tres",
		},
	}
}

func listTestSecretsKeysData() map[string]map[string]map[string][]string {
	// The "secretName" result set defined below is also used in test cases for "GetKeys()".
	return map[string]map[string]map[string][]string{
		testName: {
			"data": {
				"keys": {"one", "two", "three", "four"},
			},
		},
		testName2: {
			"data": {
				"keys": {},
			},
		},
		testName3: {
			"data": {
				"keys": {"four"},
			},
		},
		testName4: {
			"data": {
				"keys": {"four"},
			},
		},
	}
}

type ErrorMockCaller struct {
	StatusCode  int
	ReturnError bool
	DoCallCount int
	ErrorType   error
}

func (emc *ErrorMockCaller) Do(_ *http.Request) (*http.Response, error) {
	emc.DoCallCount++
	if emc.ReturnError {
		return &http.Response{
			StatusCode: emc.StatusCode,
		}, emc.ErrorType
	}

	return &http.Response{
		Body:       io.NopCloser(bytes.NewBufferString("")),
		StatusCode: emc.StatusCode,
	}, nil
}

type InMemoryMockCaller struct {
	Data                 map[string]map[string]string
	DataList             map[string]map[string][]string
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
				Body:       io.NopCloser(bytes.NewBufferString("")),
				StatusCode: 404,
			}, nil
		}
	}
	if req.Header.Get(NamespaceHeader) != testNamespace {
		return nil, errors.New("namespace header is expected but not present in request")
	}

	var testSecretName_with_prefix = "/test-service" + "/" + testName
	switch req.Method {
	case http.MethodGet:
		if req.URL.Path != testSecretName_with_prefix {
			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString("")),
				StatusCode: 404,
			}, nil
		}
		r, _ := json.Marshal(caller.Data)
		return &http.Response{
			Body:       io.NopCloser(bytes.NewBufferString(string(r))),
			StatusCode: 200,
		}, nil
	case "LIST":
		acceptedPaths := listTestSecretsKeysData()
		path := strings.Replace(req.URL.Path, "/", "", 1)
		if _, ok := acceptedPaths[path]; !ok {
			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString("")),
				StatusCode: 404,
			}, nil
		}
		r, _ := json.Marshal(caller.DataList)
		return &http.Response{
			Body:       io.NopCloser(bytes.NewBufferString(string(r))),
			StatusCode: 200,
		}, nil
	case http.MethodPost:
		if req.URL.Path != testSecretName_with_prefix {
			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString("")),
				StatusCode: 404,
			}, nil
		}
		var result map[string]string
		_ = json.NewDecoder(req.Body).Decode(&result)
		caller.Result = result
		return &http.Response{
			Body:       io.NopCloser(bytes.NewBufferString("")),
			StatusCode: 200,
		}, nil
	default:
		return nil, errors.New("unsupported HTTP method")
	}
}

func TestHttpSecretStoreManager_GetSecretNames(t *testing.T) {
	TestConnError := pkg.NewErrSecretStore("testing conn error")
	TestConnErrorSecretNameNotFound := pkg.NewErrSecretNameNotFound("testing secretName error")
	testData := listTestSecretsKeysData()
	tests := []struct {
		name              string
		basePath          string
		expectedValues    []string
		expectedErrorType error
		expectedDoCallNum int
		caller            pkg.Caller
	}{
		{
			name:              "Get three names",
			basePath:          testName,
			expectedValues:    []string{"one", "two", "three"},
			expectedErrorType: nil,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				DataList: testData[testName],
			},
		},
		{
			name:              "No names",
			basePath:          testName2,
			expectedValues:    []string{},
			expectedErrorType: nil,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				DataList: testData[testName2],
			},
		},
		{
			name:              "nil",
			basePath:          testName3,
			expectedValues:    nil,
			expectedErrorType: nil,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				DataList: testData[testName3],
			},
		},
		{
			name:              "non-existent",
			basePath:          "one",
			expectedValues:    nil,
			expectedErrorType: pkg.NewErrSecretNameNotFound("Does not exist"),
			expectedDoCallNum: 1,
			caller: &ErrorMockCaller{
				ReturnError: false,
				StatusCode:  404,
				ErrorType:   pkg.NewErrSecretNameNotFound("Does not exist"),
			},
		},
		{
			name:              "one name",
			basePath:          testName4,
			expectedValues:    []string{"four"},
			expectedErrorType: nil,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				DataList: testData[testName4],
			},
		},
		{
			name:              "Handle HTTP no secretName error",
			basePath:          testName,
			expectedValues:    nil,
			expectedErrorType: TestConnErrorSecretNameNotFound,
			expectedDoCallNum: 1,
			caller: &ErrorMockCaller{
				StatusCode: 404,
				ErrorType:  pkg.NewErrSecretNameNotFound("Not found"),
			},
		},
		{
			name:              "Handle non-200 HTTP response",
			basePath:          testName,
			expectedValues:    nil,
			expectedErrorType: TestConnError,
			expectedDoCallNum: 1,
			caller: &ErrorMockCaller{
				StatusCode: 400,
				ErrorType:  pkg.NewErrSecretStore("Error"),
			},
		},
		{
			name:              "Get Key with unknown secretName",
			basePath:          "nonexistentSecretName",
			expectedValues:    nil,
			expectedErrorType: TestConnErrorSecretNameNotFound,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				DataList: testData[testName2],
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfgHTTP := types.SecretConfig{
				Host:      "localhost",
				Port:      8080,
				Protocol:  "http",
				Namespace: testNamespace,
				BasePath:  test.basePath,
			}
			client := Client{
				Config:     cfgHTTP,
				HttpCaller: test.caller,
				lc:         logger.NewMockClient(),
			}

			actual, err := client.GetSecretNames()
			if test.expectedErrorType != nil {
				require.Error(t, err)

				eet := reflect.TypeOf(test.expectedErrorType)
				aet := reflect.TypeOf(err)
				if !aet.AssignableTo(eet) {
					t.Errorf("Expected error of type %v, but got an error of type %v", eet, aet)
				}

				return
			}

			require.NoError(t, err)
			if len(test.expectedValues) > 0 {
				require.NotEmpty(t, actual)
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

func TestHttpSecretStoreManager_GetSelfJWT(t *testing.T) {
	authToken := "some-auth-token" // nolint:gosec
	cfgHTTP := types.SecretConfig{
		Host:      "localhost",
		Port:      8080,
		Protocol:  "http",
		Namespace: testNamespace,
		Authentication: types.AuthenticationInfo{
			AuthType:  AuthTypeHeader,
			AuthToken: authToken,
		},
	}
	client := Client{
		Config: cfgHTTP,
		HttpCaller: &SimpleMockAuthHttpCaller{
			authTokenHeader: AuthTypeHeader, authToken: authToken, statusCode: 200, returnError: false,
			returnResponse: `{"data":{"token":"some-jwt-token"}}`},
		lc: logger.NewMockClient(),
	}

	actual, err := client.GetSelfJWT("my-service-key")
	require.NoError(t, err)
	require.Equal(t, "some-jwt-token", actual)
}

func TestHttpSecretStoreManager_IsJWTValid(t *testing.T) {
	authToken := "some-auth-token" // nolint:gosec
	cfgHTTP := types.SecretConfig{
		Host:      "localhost",
		Port:      8080,
		Protocol:  "http",
		Namespace: testNamespace,
		Authentication: types.AuthenticationInfo{
			AuthType:  AuthTypeHeader,
			AuthToken: authToken,
		},
	}
	client := Client{
		Config: cfgHTTP,
		HttpCaller: &SimpleMockAuthHttpCaller{
			authTokenHeader: AuthTypeHeader, authToken: authToken, statusCode: 200, returnError: false,
			returnResponse: `{"active":true}`},
		lc: logger.NewMockClient(),
	}

	actual, err := client.IsJWTValid("some-jwt-token")
	require.NoError(t, err)
	require.Equal(t, true, actual)
}
