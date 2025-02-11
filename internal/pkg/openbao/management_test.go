/*******************************************************************************
 * Copyright 2019 Dell Inc.
 * Copyright 2021 Intel Corp.
 * Copyright 2024-2025 IOTech Ltd
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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	url2 "net/url"
	"path"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"
	"github.com/edgexfoundry/go-mod-secrets/v4/pkg"
	"github.com/edgexfoundry/go-mod-secrets/v4/pkg/types"

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
		require.Contains(t, HealthAPI, r.URL.EscapedPath())
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

func TestCheckIdentityKeyExists(t *testing.T) {
	// Arrange
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "LIST", r.Method)
		require.Equal(t, oidcKeyAPI, r.URL.EscapedPath())
		require.Equal(t, expectedToken, r.Header.Get(AuthTypeHeader))

		w.WriteHeader(http.StatusOK)
		response := ListNamedKeysResponse{}
		response.Data.Keys = []string{"service1", "service2"}
		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	// Act
	exist, err := client.CheckIdentityKeyExists(expectedToken, "service2")

	// Assert
	require.NoError(t, err)
	require.Equal(t, true, exist)
}

func TestCheckIdentityKeyNotExists(t *testing.T) {
	// Arrange
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "LIST", r.Method)
		require.Equal(t, oidcKeyAPI, r.URL.EscapedPath())
		require.Equal(t, expectedToken, r.Header.Get(AuthTypeHeader))

		w.WriteHeader(http.StatusOK)
		response := ListNamedKeysResponse{}
		response.Data.Keys = []string{"service1", "service2"}
		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	// Act
	exist, err := client.CheckIdentityKeyExists(expectedToken, "service3")

	// Assert
	require.NoError(t, err)
	require.Equal(t, false, exist)
}

func TestCreateOrUpdateIdentity(t *testing.T) {
	// Arrange
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, path.Join(namedEntityAPI, "edgex-service"), r.URL.EscapedPath())
		require.Equal(t, expectedToken, r.Header.Get(AuthTypeHeader))

		var body CreateUpdateEntityRequest
		err := json.NewDecoder(r.Body).Decode(&body)
		require.NoError(t, err)
		require.Equal(t, body.Metadata["edgex-service"], "edgex-service")
		require.Equal(t, body.Policies[0], "edgex-service-policy")

		w.WriteHeader(http.StatusOK)
		response := CreateUpdateEntityResponse{}
		response.Data.ID = "someguid"
		err = json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	// Act
	theMap := make(map[string]string)
	theMap["edgex-service"] = "edgex-service"
	id, err := client.CreateOrUpdateIdentity(expectedToken, "edgex-service", theMap, []string{"edgex-service-policy"})

	// Assert
	require.NoError(t, err)
	require.Equal(t, id, "someguid")
}

func TestLookupIdentity(t *testing.T) {
	// Arrange
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, expectedToken, r.Header.Get(AuthTypeHeader))
		require.Equal(t, r.Method, http.MethodGet)
		require.Equal(t, path.Join(namedEntityAPI, "edgex-service"), r.URL.EscapedPath())

		w.WriteHeader(http.StatusOK)
		response := ReadEntityByNameResponse{}
		response.Data.ID = "someguid"
		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	// Act
	theMap := make(map[string]string)
	theMap["edgex-service"] = "edgex-service"
	id, err := client.LookupIdentity(expectedToken, "edgex-service")

	// Assert
	require.NoError(t, err)
	require.Equal(t, id, "someguid")
}

func TestGetIdentityByEntityId(t *testing.T) {
	mockId := "074fa04b-0f48-6ce3-53f3-d5cfe8147d7d"
	mockAlias := types.Alias{Name: "mockAlias1"}
	// Arrange
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, expectedToken, r.Header.Get(AuthTypeHeader))
		require.Equal(t, r.Method, http.MethodGet)
		require.Equal(t, path.Join(idEntityAPI, mockId), r.URL.EscapedPath())

		w.WriteHeader(http.StatusOK)
		response := ReadEntityByIdResponse{
			Data: types.EntityMetadata{
				Aliases: []types.Alias{mockAlias},
				ID:      mockId,
			},
		}
		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	// Act
	result, err := client.GetIdentityByEntityId(expectedToken, mockId)

	// Assert
	require.NoError(t, err)
	require.Equal(t, result.ID, mockId)
	require.Equal(t, result.Aliases[0], mockAlias)
}

func TestEnablePasswordAuth(t *testing.T) {
	// Arrange
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, path.Join(authAPI, "userauth"), r.URL.EscapedPath())
		require.Equal(t, expectedToken, r.Header.Get(AuthTypeHeader))

		var body EnableAuthMethodRequest
		err := json.NewDecoder(r.Body).Decode(&body)
		require.NoError(t, err)
		require.Equal(t, body.Type, UsernamePasswordAuthMethod)

		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	// Act
	err := client.EnablePasswordAuth(expectedToken, "userauth")

	// Assert
	require.NoError(t, err)
}

func TestLookupAuthHandle(t *testing.T) {
	// Arrange
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, authAPI, r.URL.EscapedPath())
		require.Equal(t, expectedToken, r.Header.Get(AuthTypeHeader))

		w.WriteHeader(http.StatusOK)
		response := ListAuthMethodsResponse{Data: make(map[string]Accessor)}
		response.Data["userauth/"] = Accessor{Accessor: "someguid"}
		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	// Act
	id, err := client.LookupAuthHandle(expectedToken, "userauth")

	// Assert
	require.NoError(t, err)
	require.Equal(t, id, "someguid")
}

func TestCreateOrUpdateUser(t *testing.T) {
	// Arrange
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, path.Join(authMountBase, "userauth", "users", "username"), r.URL.EscapedPath())
		require.Equal(t, expectedToken, r.Header.Get(AuthTypeHeader))

		var body CreateOrUpdateUserRequest
		err := json.NewDecoder(r.Body).Decode(&body)
		require.NoError(t, err)
		require.Equal(t, body.Password, "somepassword")
		require.Equal(t, body.TokenPeriod, "1h")
		require.Equal(t, body.TokenPolicies, []string{"a", "b"})

		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	// Act
	err := client.CreateOrUpdateUser(expectedToken, "userauth", "username", "somepassword", "1h", []string{"a", "b"})

	// Assert
	require.NoError(t, err)
}

func TestBindUserToIdentity(t *testing.T) {
	// Arrange
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, entityAliasAPI, r.URL.EscapedPath())
		require.Equal(t, expectedToken, r.Header.Get(AuthTypeHeader))

		var body CreateEntityAliasRequest
		err := json.NewDecoder(r.Body).Decode(&body)
		require.NoError(t, err)
		require.Equal(t, body.Name, "username")
		require.Equal(t, body.CanonicalID, "identityid")
		require.Equal(t, body.MountAccessor, "authhandle")

		w.WriteHeader(http.StatusOK)
		// Don't care about the response at this time
	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	// Act
	err := client.BindUserToIdentity(expectedToken, "identityid", "authhandle", "username")

	// Assert
	require.NoError(t, err)
}

func createClient(t *testing.T, url string, lc logger.LoggingClient) *Client {
	urlDetails, err := url2.Parse(url)
	require.NoError(t, err)
	port, err := strconv.Atoi(urlDetails.Port())
	require.NoError(t, err)

	config := types.SecretConfig{
		Type:     "openbao",
		Protocol: urlDetails.Scheme,
		Host:     urlDetails.Hostname(),
		Port:     port,
	}

	client, err := NewClient(config, pkg.NewMockRequester().Insecure(), false, lc)
	require.NoError(t, err)

	return client
}
