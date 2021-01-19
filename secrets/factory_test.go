package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/edgexfoundry/go-mod-secrets/v2/pkg"
	"github.com/edgexfoundry/go-mod-secrets/v2/pkg/providers/vault"
	"github.com/edgexfoundry/go-mod-secrets/v2/pkg/types"

	"github.com/edgexfoundry/go-mod-core-contracts/v2/clients/logger"
)

func TestNewSecretClient(t *testing.T) {
	authToken := "testToken"
	var tokenDataMap sync.Map
	tokenDataMap.Store(authToken, vault.TokenLookupMetadata{
		Renewable: true,
		Ttl:       10000,
		Period:    10000,
	})
	server := getMockTokenServer(&tokenDataMap)
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Errorf("error on parsing server url %s: %s", server.URL, err)
	}
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
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			factory := newSecretClientFactory()

			emptyTokenCallbackFunc := func(expiredToken string) (replacementToken string, retry bool) {
				return "", false
			}
			c, err := factory.NewSecretClient(bkgCtx, tt.cfg, mockLogger, emptyTokenCallbackFunc)
			if err != nil {
				if !tt.expectErr {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if tt.expectErr {
					t.Errorf("did not receive expected error: %s", tt.name)
				}
				if tt.expectedTime != nil {
					if client, ok := c.(vault.Client); ok {
						if *tt.expectedTime != client.HttpConfig.RetryWaitPeriodTime {
							t.Errorf("expected parsed time as %v, got %v", *tt.expectedTime, client.HttpConfig.RetryWaitPeriodTime)
						}
					} else {
						t.Errorf("returned client type is not Client, is %T", c)
					}
				}
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
	tokenDataMap.Store("testToken1", vault.TokenLookupMetadata{
		Renewable: true,
		Ttl:       tokenPeriod * 7 / 10,
		Period:    tokenPeriod,
	})
	// ttl = half of period
	tokenDataMap.Store("testToken2", vault.TokenLookupMetadata{
		Renewable: true,
		Ttl:       tokenPeriod / 2,
		Period:    tokenPeriod,
	})
	// ttl < half of period
	tokenDataMap.Store("testToken3", vault.TokenLookupMetadata{
		Renewable: true,
		Ttl:       tokenPeriod * 3 / 10,
		Period:    tokenPeriod,
	})
	// to be expired token
	tokenDataMap.Store("toToExpiredToken", vault.TokenLookupMetadata{
		Renewable: true,
		Ttl:       1,
		Period:    tokenPeriod,
	})
	// expired token
	tokenDataMap.Store("expiredToken", vault.TokenLookupMetadata{
		Renewable: true,
		Ttl:       0,
		Period:    tokenPeriod,
	})
	// not renewable token
	tokenDataMap.Store("unrenewableToken", vault.TokenLookupMetadata{
		Renewable: false,
		Ttl:       0,
		Period:    tokenPeriod,
	})

	server := getMockTokenServer(&tokenDataMap)
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Errorf("error on parsing server url %s: %s", server.URL, err)
	}
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
			expectedErrorType: vault.ErrHTTPResponse{StatusCode: 403, ErrMsg: "forbidden"},
		},
		{
			name:              "New secret client with expired token, no TTL remaining, 3 retries",
			authToken:         "expiredToken",
			retries:           3,
			expectError:       true,
			expectedErrorType: vault.ErrHTTPResponse{StatusCode: 403, ErrMsg: "forbidden"},
		},
		{
			name:              "New secret client with unauthenticated token",
			authToken:         "invalidToken",
			expectError:       true,
			expectedErrorType: vault.ErrHTTPResponse{StatusCode: 403, ErrMsg: "forbidden"},
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

	factory := newSecretClientFactory()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfgHTTP := types.SecretConfig{
				Host:                    host,
				Port:                    portNum,
				Protocol:                "http",
				Authentication:          types.AuthenticationInfo{AuthToken: test.authToken},
				AdditionalRetryAttempts: test.retries,
			}

			c, err := factory.NewSecretClient(bkgCtx, cfgHTTP, mockLogger, test.tokenExpiredCallbackFunc)

			if test.expectedErrorType != nil && err == nil {
				t.Errorf("Expected error %v but none was received", test.expectedErrorType)
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

			client := c.(vault.Client)

			// look up the token data again after renewal
			lookupTokenData, err := client.GetTokenLookupResponseData()
			if !test.expectError && err != nil {
				t.Errorf("error on cfgAuthToken %s: %s", test.authToken, err)
			}

			if !test.expectError && lookupTokenData != nil && lookupTokenData.Data.Renewable &&
				lookupTokenData.Data.Ttl < tokenPeriod/2 {
				tokenData, _ := tokenDataMap.Load(test.authToken)
				tokenTTL := tokenData.(vault.TokenLookupMetadata).Ttl
				t.Errorf("failed to renew token with the token period %d: the current TTL %d and the old TTL: %d",
					tokenPeriod, lookupTokenData.Data.Ttl, tokenTTL)
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
	tokenDataMap.Store("expiredToken", vault.TokenLookupMetadata{
		Renewable: true,
		Ttl:       0,
		Period:    tokenPeriod,
	})

	server := getMockTokenServer(&tokenDataMap)
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Errorf("error on parsing server url %s: %s", server.URL, err)
	}
	host, port, _ := net.SplitHostPort(serverURL.Host)
	portNum, _ := strconv.Atoi(port)

	bkgCtx := context.Background()

	mockLogger := logger.NewMockClient()
	factory := newSecretClientFactory()
	cfgHTTP := types.SecretConfig{
		Host:           host,
		Port:           portNum,
		Protocol:       "http",
		Authentication: types.AuthenticationInfo{AuthToken: "expiredToken"},
	}

	emptyTokenCallbackFunc := func(expiredToken string) (replacementToken string, retry bool) {
		return "", false
	}
	_, err = factory.NewSecretClient(bkgCtx, cfgHTTP, mockLogger, emptyTokenCallbackFunc)
	// it will fail since the token is expired
	if err == nil {
		t.Errorf("expecting an error for expired token")
	}

	// create a second secret client with the same expired token
	_, err = factory.NewSecretClient(bkgCtx, cfgHTTP, mockLogger, emptyTokenCallbackFunc)
	if err == nil {
		t.Errorf("expecting an error for expired token")
	} else {
		fmt.Println(err)
	}
	// wait for some time to allow renewToken to be run if any
	time.Sleep(10 * time.Second)
}

func TestConcurrentSecretClientTokenRenewals(t *testing.T) {
	// run in parallel with other tests
	t.Parallel()
	// setup
	tokenPeriod := 6
	var tokenDataMap sync.Map

	// ttl < half of period
	tokenDataMap.Store("testToken3", vault.TokenLookupMetadata{
		Renewable: true,
		Ttl:       tokenPeriod * 3 / 10,
		Period:    tokenPeriod,
	})

	server := getMockTokenServer(&tokenDataMap)
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Errorf("error on parsing server url %s: %s", server.URL, err)
	}
	host, port, _ := net.SplitHostPort(serverURL.Host)
	portNum, _ := strconv.Atoi(port)

	bkgCtx := context.Background()
	mockLogger := logger.NewMockClient()
	factory := newSecretClientFactory()
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
			_, err = factory.NewSecretClient(bkgCtx, cfgHTTP, mockLogger, emptyTokenCallbackFunc)
			// verify if any error
			if err != nil {
				t.Errorf("found error in secret client %d: %v", ith, err)
			}
			time.Sleep(15 * time.Second)
		}(i)
	}

	// wait for some time to allow renewToken to be run if any
	time.Sleep(15 * time.Second)
}

func getMockTokenServer(tokenDataMap *sync.Map) *httptest.Server {

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		urlPath := req.URL.String()
		if req.Method == http.MethodGet && urlPath == "/v1/auth/token/lookup-self" {
			token := req.Header.Get(vault.AuthTypeHeader)
			sampleTokenLookup, exists := tokenDataMap.Load(token)
			if !exists {
				rw.WriteHeader(403)
				_, _ = rw.Write([]byte("permission denied"))
			} else {
				resp := &vault.TokenLookupResponse{
					Data: sampleTokenLookup.(vault.TokenLookupMetadata),
				}
				if ret, err := json.Marshal(resp); err != nil {
					rw.WriteHeader(500)
					_, _ = rw.Write([]byte(err.Error()))
				} else {
					rw.WriteHeader(200)
					_, _ = rw.Write(ret)
				}
			}
		} else if req.Method == http.MethodPost && urlPath == "/v1/auth/token/renew-self" {
			token := req.Header.Get(vault.AuthTypeHeader)
			sampleTokenLookup, exists := tokenDataMap.Load(token)
			if !exists {
				rw.WriteHeader(403)
				_, _ = rw.Write([]byte("permission denied"))
			} else {
				currentTTL := sampleTokenLookup.(vault.TokenLookupMetadata).Ttl
				if currentTTL <= 0 {
					// already expired
					rw.WriteHeader(403)
					_, _ = rw.Write([]byte("permission denied"))
				} else {
					tokenPeriod := sampleTokenLookup.(vault.TokenLookupMetadata).Period

					tokenDataMap.Store(token, vault.TokenLookupMetadata{
						Renewable: true,
						Ttl:       tokenPeriod,
						Period:    tokenPeriod,
					})
					rw.WriteHeader(200)
					_, _ = rw.Write([]byte("token renewed"))
				}
			}
		} else {
			rw.WriteHeader(404)
			_, _ = rw.Write([]byte(fmt.Sprintf("Unknown urlPath: %s", urlPath)))
		}
	}))
	return server
}
