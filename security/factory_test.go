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

package security

import (
	"os"
	"testing"

	"github.com/edgexfoundry-holding/go-mod-core-security/pkg/types"

	"github.com/edgexfoundry-holding/go-mod-core-security/internal/pkg/vault"
)

var validTestConfig = types.Config{Provider: types.VaultProvider}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func TestNewSecurityClient(t *testing.T) {
	c, err := NewSecurityClient(validTestConfig)

	emptyClient := vault.Client{}
	if c == emptyClient {
		t.Error("Empty client returned from factory method")
	}

	if err != nil {
		t.Error(err)
	}
}

func TestNewSecurityClientUnknownProvider(t *testing.T) {
	c, err := NewSecurityClient(types.Config{Provider: "invalid"})

	if c != nil {
		t.Error("Expected nil for error case")
	}

	if err == nil {
		t.Error("Expected error for error case")
	}
}
