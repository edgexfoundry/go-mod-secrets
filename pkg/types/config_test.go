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

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildUrl(t *testing.T) {
	cfgNoPath := SecretConfig{Host: "localhost", Port: 8080, Protocol: "http"}
	cfgWithPath := SecretConfig{Host: "localhost", Port: 8080, Protocol: "http", BasePath: "/ping"}
	cfgWithTrailingSlash := SecretConfig{Host: "localhost", Port: 8080, Protocol: "http", BasePath: "/api/v1/ping/"}
	cfgWithNoHost := SecretConfig{Host: "", Port: 8080, Protocol: "http", BasePath: ""}
	cfgWithInvalidHost := SecretConfig{Host: "not valid", Port: 8080, Protocol: "http", BasePath: ""}
	cfgWithUnsetPort := SecretConfig{Host: "", Port: 0, Protocol: "http", BasePath: "/api/v1/ping/"}
	cfgWithInvalidPort := SecretConfig{Host: "", Port: 9999, Protocol: "http", BasePath: "/api/v1/ping/"}
	cfgWithNoProtocol := SecretConfig{Host: "localhost", Port: 8080, Protocol: "", BasePath: "/api/v1/ping/"}
	cfgWithInvalidProtocol := SecretConfig{Host: "localhost", Port: 8080, Protocol: "234", BasePath: ""}

	tests := []struct {
		name        string
		cfg         SecretConfig
		path        string
		expectError bool
	}{
		{"Valid - No Path", cfgNoPath, "http://localhost:8080/", false},
		{"Valid - With Path", cfgWithPath, "http://localhost:8080/ping", false},
		{"Valid - With Trailing Slash", cfgWithTrailingSlash, "http://localhost:8080/api/v1/ping", false},
		{"Invalid - No Host", cfgWithNoHost, "", true},
		{"Invalid - Invalid Host", cfgWithInvalidHost, "", true},
		{"Invalid - unset Port", cfgWithUnsetPort, "", true},
		{"Invalid - Invalid Port", cfgWithInvalidPort, "", true},
		{"Invalid - No protocol", cfgWithNoProtocol, "", true},
		{"Invalid - Invalid protocol", cfgWithInvalidProtocol, "", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			val, err := test.cfg.BuildURL(test.cfg.BasePath)
			if test.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.path, val)
		})
	}
}
