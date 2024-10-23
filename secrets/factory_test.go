/*******************************************************************************
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

package secrets

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/edgexfoundry/go-mod-secrets/v4/internal/pkg/openbao"
	"github.com/edgexfoundry/go-mod-secrets/v4/pkg"
	"github.com/edgexfoundry/go-mod-secrets/v4/pkg/types"

	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"
)

func TestNewSecretsClient(t *testing.T) {
	mockLogger := logger.NewMockClient()

	tokenPeriod := 6
	var tokenDataMap sync.Map
	// ttl > half of period
	tokenDataMap.Store("TestToken", openbao.TokenLookupResponse{
		Data: types.TokenMetadata{
			Renewable: true,
			Ttl:       tokenPeriod * 7 / 10,
			Period:    tokenPeriod,
		},
	})

	server := openbao.GetMockTokenServer(&tokenDataMap)
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	host, port, _ := net.SplitHostPort(serverURL.Host)
	portNum, _ := strconv.Atoi(port)

	tests := []struct {
		Name        string
		Ctx         context.Context
		Type        string
		ExpectError bool
	}{
		{"Valid", context.Background(), DefaultSecretStore, false},
		{"Invalid - no context", nil, DefaultSecretStore, true},
		{"Invalid - bad type", context.Background(), "BAD", true},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			config := types.SecretConfig{
				Type:     test.Type,
				Host:     host,
				Protocol: "http",
				Port:     portNum,
				Authentication: types.AuthenticationInfo{
					AuthToken: "TestToken",
				},
			}

			client, err := NewSecretsClient(test.Ctx, config, mockLogger, nil)
			if test.ExpectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, client)
		})
	}
}

func TestNewSecretStoreClient(t *testing.T) {
	mockLogger := logger.NewMockClient()

	tests := []struct {
		Name        string
		Type        string
		ExpectError bool
	}{
		{"Valid", DefaultSecretStore, false},
		{"Invalid - bad type", "BAD", true},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			config := types.SecretConfig{
				Type: test.Type,
			}

			client, err := NewSecretStoreClient(config, mockLogger, pkg.NewMockRequester().Insecure())
			if test.ExpectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, client)
		})
	}
}
