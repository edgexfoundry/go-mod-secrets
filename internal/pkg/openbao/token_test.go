//
// Copyright (c) 2021 Intel Corporation
// Copyright 2025 IOTech Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.
//

package openbao

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateToken(t *testing.T) {
	// Arrange
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, CreateTokenAPI, r.URL.EscapedPath())
		require.Equal(t, expectedToken, r.Header.Get(AuthTypeHeader))

		body := make(map[string]interface{})
		err := json.NewDecoder(r.Body).Decode(&body)
		assert.NoError(t, err)

		assert.Equal(t, "sample-value", body["sample_parameter"])

		w.WriteHeader(http.StatusOK)

		response := struct {
			RequestID string `json:"request_id"`
		}{
			RequestID: "f00341c1-fad5-f6e6-13fd-235617f858a1",
		}
		err = json.NewEncoder(w).Encode(response)
		assert.NoError(t, err)

	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	// Act
	parameters := make(map[string]interface{})
	parameters["sample_parameter"] = "sample-value"
	response, err := client.CreateToken(expectedToken, parameters)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "f00341c1-fad5-f6e6-13fd-235617f858a1", response["request_id"].(string))
}

func TestCreateTokenByRole(t *testing.T) {
	mockRole := "role1"

	// Arrange
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, fmt.Sprintf(CreateTokenByRolePath, mockRole), r.URL.EscapedPath())
		require.Equal(t, expectedToken, r.Header.Get(AuthTypeHeader))

		body := make(map[string]interface{})
		err := json.NewDecoder(r.Body).Decode(&body)
		assert.NoError(t, err)

		assert.Equal(t, "sample-value", body["sample_parameter"])

		w.WriteHeader(http.StatusOK)

		response := struct {
			RequestID string `json:"request_id"`
		}{
			RequestID: "f00341c1-fad5-f6e6-13fd-235617f858a1",
		}
		err = json.NewEncoder(w).Encode(response)
		assert.NoError(t, err)

	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	// Act
	parameters := make(map[string]interface{})
	parameters["sample_parameter"] = "sample-value"
	response, err := client.CreateTokenByRole(expectedToken, mockRole, parameters)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "f00341c1-fad5-f6e6-13fd-235617f858a1", response["request_id"].(string))
}

func TestListTokenAccessors(t *testing.T) {
	// Arrange
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "LIST", r.Method)
		require.Equal(t, ListAccessorsAPI, r.URL.EscapedPath())
		require.Equal(t, expectedToken, r.Header.Get(AuthTypeHeader))

		// No body for this request

		w.WriteHeader(http.StatusOK)

		response := struct {
			Data interface{} `json:"data"`
		}{
			Data: struct {
				Keys []string `json:"keys"`
			}{
				Keys: []string{"accessor1", "accessor2"},
			},
		}
		err := json.NewEncoder(w).Encode(response)
		assert.NoError(t, err)

	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	// Act
	response, err := client.ListTokenAccessors(expectedToken)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "accessor1", response[0])
	assert.Equal(t, "accessor2", response[1])
}

func TestRevokeTokenAccessor(t *testing.T) {
	// Arrange
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, RevokeAccessorAPI, r.URL.EscapedPath())
		require.Equal(t, expectedToken, r.Header.Get(AuthTypeHeader))

		body := make(map[string]interface{})
		err := json.NewDecoder(r.Body).Decode(&body)
		require.NoError(t, err)

		require.Equal(t, "accessor1", body["accessor"])

		w.WriteHeader(http.StatusNoContent)

		// no response body
	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	// Act
	err := client.RevokeTokenAccessor(expectedToken, "accessor1")

	// Assert
	require.NoError(t, err)
}

func TestLookupTokenAccessor(t *testing.T) {
	// Arrange
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, LookupAccessorAPI, r.URL.EscapedPath())
		require.Equal(t, expectedToken, r.Header.Get(AuthTypeHeader))

		body := make(map[string]interface{})
		err := json.NewDecoder(r.Body).Decode(&body)
		require.NoError(t, err)

		require.Equal(t, "8609694a-cdbc-db9b-d345-e782dbb562ed", body["accessor"])

		w.WriteHeader(http.StatusOK)

		response := struct {
			Data interface{} `json:"data"`
		}{
			Data: struct {
				Accessor string `json:"accessor"`
			}{
				Accessor: "accessor-value",
			},
		}
		err = json.NewEncoder(w).Encode(response)
		require.NoError(t, err)

	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	// Act
	tokenData, err := client.LookupTokenAccessor(expectedToken, "8609694a-cdbc-db9b-d345-e782dbb562ed")

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "accessor-value", tokenData.Accessor)
}

func TestLookupToken(t *testing.T) {
	// Arrange
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, LookupSelfAPI, r.URL.EscapedPath())
		require.Equal(t, expectedToken, r.Header.Get(AuthTypeHeader))

		// No body for this request

		w.WriteHeader(http.StatusOK)

		response := struct {
			Data interface{} `json:"data"`
		}{
			Data: struct {
				Accessor string `json:"accessor"`
			}{
				Accessor: "accessor-value",
			},
		}
		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)

	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	// Act
	tokenData, err := client.LookupToken(expectedToken)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "accessor-value", tokenData.Accessor)
}

func TestRevokeToken(t *testing.T) {
	// Arrange
	mockLogger := logger.MockLogger{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, RevokeSelfAPI, r.URL.EscapedPath())
		require.Equal(t, expectedToken, r.Header.Get(AuthTypeHeader))

		// No body, no response body for this request

		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	// Act
	err := client.RevokeToken(expectedToken)

	// Assert
	require.NoError(t, err)
}
