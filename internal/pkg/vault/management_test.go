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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	url2 "net/url"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/edgexfoundry/go-mod-secrets/v2/pkg"
	"github.com/edgexfoundry/go-mod-secrets/v2/pkg/types"

	"github.com/edgexfoundry/go-mod-core-contracts/v2/clients/logger"

	"github.com/stretchr/testify/assert"
)

const (
	expectedToken      = "fake-token"
	testBootstrapToken = "test-bootstrap-token"
)

func TestHealthCheck(t *testing.T) {
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, HealthAPI, r.URL.EscapedPath())
	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	code, err := client.HealthCheck()
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
}

func TestHealthCheckUninitialized(t *testing.T) {
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	code, err := client.HealthCheck()
	require.Error(t, err)
	assert.Equal(t, http.StatusNotImplemented, code)
}

func TestHealthCheckSealed(t *testing.T) {
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	code, err := client.HealthCheck()
	require.Error(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, code)
}

func TestInit(t *testing.T) {
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{
			"keys": [
			  "test-keys"
			],
			"keys_base64": [
			  "test-keys-base64"
			],
			"root_token": "test-root-token"
		}
		`))
		require.NoError(t, err)
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, InitAPI, r.URL.EscapedPath())
	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	initResp, err := client.Init(1, 2)
	require.NoError(t, err)
	assert.NotNil(t, initResp)
}

func TestUnseal(t *testing.T) {
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"sealed": false, "t": 1, "n": 1, "progress": 100}`))
		require.NoError(t, err)
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, UnsealAPI, r.URL.EscapedPath())
	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	err := client.Unseal([]string{"test-keys-base64"})
	require.NoError(t, err)
}

func TestInstallPolicy(t *testing.T) {
	mockLogger := logger.MockLogger{}
	expected := "policydoc"

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		require.Equal(t, "/v1/sys/policies/acl/policy-name", r.URL.EscapedPath())
		require.Equal(t, expectedToken, r.Header.Get(AuthTypeHeader))

		// Make sure the policy doc was base64 encoded in the json response object
		body := make(map[string]interface{})
		err := json.NewDecoder(r.Body).Decode(&body)
		require.NoError(t, err)
		require.Equal(t, expected, body["policy"].(string))

		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	// Act
	err := client.InstallPolicy(expectedToken, "policy-name", expected)

	// Assert
	require.NoError(t, err)
}

func TestCheckSecretEngineInstalled(t *testing.T) {
	// Arrange
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, MountsAPI, r.URL.EscapedPath())
		require.Equal(t, expectedToken, r.Header.Get(AuthTypeHeader))

		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{
			"data": {
				"cubbyhole/": {
					"accessor": "cubbyhole_23676773",
					"config": {
						"default_lease_ttl": 0,
						"force_no_cache": false,
						"max_lease_ttl": 0
					},
					"description": "per-token private secret storage",
					"local": true,
					"options": null,
					"seal_wrap": false,
					"type": "cubbyhole"
				},
				"identity/": {
					"accessor": "identity_11e23ad0",
					"config": {
						"default_lease_ttl": 0,
						"force_no_cache": false,
						"max_lease_ttl": 0
					},
					"description": "identity store",
					"local": false,
					"options": null,
					"seal_wrap": false,
					"type": "identity"
				},
				"secret/": {
					"accessor": "kv_3ee7b0c0",
					"config": {
						"default_lease_ttl": 0,
						"force_no_cache": false,
						"max_lease_ttl": 0
					},
					"description": "key/value secret storage",
					"local": false,
					"options": {
						"version": "1"
					},
					"seal_wrap": false,
					"type": "kv"
				},
				"consul/": {
					"accessor": "consul_cb2f6638",
					"config": {
					  "default_lease_ttl": 0,
					  "force_no_cache": false,
					  "max_lease_ttl": 0
					},
					"description": "consul secret storage",
					"external_entropy_access": false,
					"local": false,
					"options": {},
					"seal_wrap": false,
					"type": "consul",
					"uuid": "512886f9-61e1-d662-dd1b-d583f20e1875"
				},
				"sys/": {
					"accessor": "system_5e0c411d",
					"config": {
						"default_lease_ttl": 0,
						"force_no_cache": false,
						"max_lease_ttl": 0
					},
					"description": "system endpoints used for control, policy and debugging",
					"local": false,
					"options": null,
					"seal_wrap": false,
					"type": "system"
				}
			}	
		  }`))
		require.NoError(t, err)

	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	tests := []struct {
		name       string
		mountPath  string
		engineType string
	}{
		{"kv v1 secret storage installed", "secret/", KeyValue},
		{"consul secret storage installed", "consul/", Consul},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Act
			installed, err := client.CheckSecretEngineInstalled("fake-token", test.mountPath, test.engineType)

			// Assert
			require.NoError(t, err)
			require.True(t, installed)
		})
	}
}

func TestCheckSecretEngineNotInstalled(t *testing.T) {
	// Arrange
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, MountsAPI, r.URL.EscapedPath())
		require.Equal(t, expectedToken, r.Header.Get(AuthTypeHeader))

		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{
			"data": {
				"cubbyhole/": {
					"accessor": "cubbyhole_23676773",
					"config": {
						"default_lease_ttl": 0,
						"force_no_cache": false,
						"max_lease_ttl": 0
					},
					"description": "per-token private secret storage",
					"local": true,
					"options": null,
					"seal_wrap": false,
					"type": "cubbyhole"
				},
				"identity/": {
					"accessor": "identity_11e23ad0",
					"config": {
						"default_lease_ttl": 0,
						"force_no_cache": false,
						"max_lease_ttl": 0
					},
					"description": "identity store",
					"local": false,
					"options": null,
					"seal_wrap": false,
					"type": "identity"
				},
				"kv/": {
					"accessor": "kv_3ee7b0c0",
					"config": {
						"default_lease_ttl": 0,
						"force_no_cache": false,
						"max_lease_ttl": 0
					},
					"description": "key/value secret storage",
					"local": false,
					"options": {
						"version": "1"
					},
					"seal_wrap": false,
					"type": "kv"
				},
				"sys/": {
					"accessor": "system_5e0c411d",
					"config": {
						"default_lease_ttl": 0,
						"force_no_cache": false,
						"max_lease_ttl": 0
					},
					"description": "system endpoints used for control, policy and debugging",
					"local": false,
					"options": null,
					"seal_wrap": false,
					"type": "system"
				}
			}	
		  }`))
		require.NoError(t, err)
	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	tests := []struct {
		name       string
		mountPath  string
		engineType string
	}{
		{"kv v1 secret storage not installed", "secret/", KeyValue},
		{"consul secret storage not installed", "consul/", Consul},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Act
			installed, err := client.CheckSecretEngineInstalled("fake-token", test.mountPath, test.engineType)

			// Assert
			require.NoError(t, err)
			require.False(t, installed)
		})
	}
}

func TestEnableKVSecretEngine(t *testing.T) {
	// Arrange
	mockLogger := logger.MockLogger{}

	expectedType := KeyValue
	expectedVersion := "1"
	expectedMountPoint := "secret"

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, MountsAPI+"/"+expectedMountPoint, r.URL.EscapedPath())
		require.Equal(t, expectedToken, r.Header.Get(AuthTypeHeader))

		var body EnableSecretsEngineRequest
		err := json.NewDecoder(r.Body).Decode(&body)
		require.NoError(t, err)
		require.Equal(t, expectedType, body.Type)
		require.Equal(t, expectedVersion, body.Options.Version)

		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	// Act
	err := client.EnableKVSecretEngine(expectedToken, expectedMountPoint+"/", expectedVersion)

	// Assert
	require.NoError(t, err)
}

func TestEnableConsulSecretEngine(t *testing.T) {
	// Arrange
	mockLogger := logger.MockLogger{}

	expectedType := Consul
	expectedTTL := "1h"
	expectedMountPoint := "consul"

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, MountsAPI+"/"+expectedMountPoint, r.URL.EscapedPath())
		require.Equal(t, expectedToken, r.Header.Get(AuthTypeHeader))

		var body EnableSecretsEngineRequest
		err := json.NewDecoder(r.Body).Decode(&body)
		require.NoError(t, err)
		require.Equal(t, expectedType, body.Type)
		require.Equal(t, expectedTTL, body.Config.DefaultLeaseTTLDuration)

		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	// Act
	err := client.EnableConsulSecretEngine(expectedToken, expectedMountPoint+"/", expectedTTL)

	// Assert
	require.NoError(t, err)
}

func TestConfigureConsulAccess(t *testing.T) {
	mockLogger := logger.MockLogger{}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	client := createClient(t, ts.URL, mockLogger)
	err := client.ConfigureConsulAccess(expectedToken, testBootstrapToken, "test-host", 8888)
	require.NoError(t, err)
}

func TestCreateRole(t *testing.T) {
	testSinglePolicy := []types.Policy{
		{
			ID:   "test-ID",
			Name: "test-name",
		},
	}
	testMultiplePolicies := []types.Policy{
		{
			ID:   "test-ID1",
			Name: "test-name1",
		},
		{
			ID:   "test-ID2",
			Name: "test-name2",
		},
	}

	testRoleWithNilPolicy := types.NewConsulRole("testRoleSingle", "client", nil, true)
	testRoleWithEmptyPolicy := types.NewConsulRole("testRoleSingle", "client", []types.Policy{}, true)
	testRoleWithSinglePolicy := types.NewConsulRole("testRoleSingle", "client", testSinglePolicy, true)
	testRoleWithMultiplePolicies := types.NewConsulRole("testRoleMultiple", "client", testMultiplePolicies, true)
	testEmptyRoleName := types.NewConsulRole("", "management", testSinglePolicy, true)
	testCreateRoleErr := errors.New("request to create Role failed with status: 403 Forbidden")
	testEmptyTokenErr := errors.New("required secret store token is empty")
	testEmptyRoleNameErr := errors.New("required Consul role name is empty")

	tests := []struct {
		name             string
		secretstoreToken string
		consulRole       types.ConsulRole
		httpStatusCode   int
		expectedErr      error
	}{
		{"Good:create role with single policy ok", "test-secretstore-token", testRoleWithSinglePolicy, http.StatusNoContent, nil},
		{"Good:create role with multiple policies ok", expectedToken, testRoleWithMultiplePolicies, http.StatusNoContent, nil},
		{"Good:create role with empty policy ok", expectedToken, testRoleWithEmptyPolicy, http.StatusNoContent, nil},
		{"Good:create role with nil policy ok", "test-secretstore-token", testRoleWithNilPolicy, http.StatusNoContent, nil},
		{"Bad:create role bad response", expectedToken, testRoleWithSinglePolicy, http.StatusForbidden, testCreateRoleErr},
		{"Bad:empty secretstore token", "", testRoleWithMultiplePolicies, http.StatusForbidden, testEmptyTokenErr},
		{"Bad:empty role name", expectedToken, testEmptyRoleName, http.StatusForbidden, testEmptyRoleNameErr},
	}

	for _, tt := range tests {
		test := tt // capture as local copy
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			// prepare test
			mockLogger := logger.MockLogger{}
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.httpStatusCode)
			}))
			defer ts.Close()
			client := createClient(t, ts.URL, mockLogger)
			err := client.CreateRole(test.secretstoreToken, test.consulRole)
			if test.expectedErr != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func createClient(t *testing.T, url string, lc logger.LoggingClient) *Client {
	urlDetails, err := url2.Parse(url)
	require.NoError(t, err)
	port, err := strconv.Atoi(urlDetails.Port())
	require.NoError(t, err)

	config := types.SecretConfig{
		Type:     "vault",
		Protocol: urlDetails.Scheme,
		Host:     urlDetails.Hostname(),
		Port:     port,
	}

	client, err := NewClient(config, pkg.NewMockRequester().Insecure(), false, lc)
	require.NoError(t, err)

	return client
}
