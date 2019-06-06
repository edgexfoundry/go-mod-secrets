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

// Package HTTP defines the implementation specific details for a REST HTTP key store.
package pkg

import (
	"testing"

	"github.com/edgexfoundry-holding/go-mod-core-security/pkg/errors"
	"github.com/edgexfoundry-holding/go-mod-core-security/pkg/mocks"
)

var TestClient = SecretClient{
	Manager: mocks.MockSecretStoreManager{
		Secrets: map[string]string{
			"one":   "uno",
			"two":   "dos",
			"three": "tres",
		}}}

func TestSecretClient_GetSecret(t *testing.T) {
	actual, err := TestClient.GetSecret("one")
	if err != nil {
		t.Error("Failed to obtain value: " + err.Error())
	}

	if actual != "uno" {
		t.Errorf("Failed to obtain the correct value. Expecting: '%s' , but got: '%s'", "uno", actual)
	}
}

func TestSecretClient_SetSecret(t *testing.T) {
	_ = TestClient.SetSecret("four", "cuatro")
	actual, err := TestClient.GetSecret("four")
	if err != nil {
		t.Error("Failed to obtain value: " + err.Error())
	}

	if actual != "cuatro" {
		t.Errorf("Failed to obtain the correct value. Expecting: '%s' , but got: '%s'", "cuatro", actual)
	}
}

func TestSecretClient_DeleteKey(t *testing.T) {
	TestClient.DeleteKey("one")
	_, err := TestClient.GetSecret("one")
	if err == nil {
		t.Error("Expected an error")
	}

	switch err.(type) {
	case errors.ErrSecretNotFound:
	// Expected
	default:
		t.Errorf("Expected error of type ErrSecretNotFound, but got %v", err)
	}
}
