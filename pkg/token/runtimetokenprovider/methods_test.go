//
// Copyright (c) 2022 Intel Corporation
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
// SPDX-License-Identifier: Apache-2.0'
//

package runtimetokenprovider

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"
	"github.com/edgexfoundry/go-mod-secrets/v4/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestNewRuntimeTokenProvider(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	mockLogger := logger.NewMockClient()
	testProviderConf := types.RuntimeTokenProviderInfo{
		Enabled:        true,
		Protocol:       "http",
		Host:           "localhost",
		Port:           8888,
		TrustDomain:    "test.domain",
		EndpointSocket: "/tmp/edgex/socket",
	}
	provider := NewRuntimeTokenProvider(ctx, mockLogger, testProviderConf)
	require.NotEmpty(t, provider)
}

func TestGetRawToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	mockLogger := logger.NewMockClient()

	testHTTPServer := newTestServer(serverOptions{})
	testHTTPServer.setupTestServer(t)
	defer testHTTPServer.close()

	testServerURL, err := url.Parse(testHTTPServer.server.URL)
	require.NoError(t, err)
	testServerHost, testServerPort, err := net.SplitHostPort(testServerURL.Host)
	require.NoError(t, err)
	portNum, err := strconv.Atoi(testServerPort)
	require.NoError(t, err)

	testProviderConf := types.RuntimeTokenProviderInfo{
		Enabled:        true,
		Protocol:       testServerURL.Scheme,
		Host:           testServerHost,
		Port:           portNum,
		TrustDomain:    "test.domain",
		EndpointSocket: "/tmp/edgex/socket",
	}

	provider := NewRuntimeTokenProvider(ctx, mockLogger, testProviderConf)

	// mock the TLSConfig part as this is no real spiffe server in the unit tests
	(provider.(*runtimetokenprovider)).SetTLSConfigFunc(func(context.Context, logger.LoggingClient) (*tls.Config, error) {
		return &tls.Config{MinVersion: tls.VersionTLS13}, nil
	})

	token, err := provider.GetRawToken("service-key")
	require.NoError(t, err)
	require.NotEmpty(t, token)
}
