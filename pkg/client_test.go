/*******************************************************************************
 * Copyright 2019 Dell Inc.
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

package pkg

import (
	"testing"
)

func TestNewSecretClient(t *testing.T) {
	cfgHttp := SecretConfig{Host: "localhost", Port: 8080, Protocol: "http"}
	cfgNoop := SecretConfig{Host: "localhost", Port: 8080, Protocol: "mqtt"}

	tests := []struct {
		name      string
		cfg       SecretConfig
		expectErr bool
	}{
		{"newHttp", cfgHttp, false},
		{"newNoop", cfgNoop, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSecretClient(tt.cfg)
			if err != nil {
				if !tt.expectErr {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if tt.expectErr {
					t.Errorf("did not receive expected error: %s", tt.name)
				}
			}
		})
	}
}
