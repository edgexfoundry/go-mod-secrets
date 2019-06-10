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

	"github.com/edgexfoundry/go-mod-secrets/pkg/errors"
	"github.com/edgexfoundry/go-mod-secrets/pkg/mocks"
)

var TestClient = SecretClient{
	Manager: mocks.MockSecretStoreManager{
		Secrets: map[string]string{
			"one":   "uno",
			"two":   "dos",
			"three": "tres",
		}}}

func reset() {
	TestClient = SecretClient{
		Manager: mocks.MockSecretStoreManager{
			Secrets: map[string]string{
				"one":   "uno",
				"two":   "dos",
				"three": "tres",
			}}}
}

func TestSecretClient_GetSecret(t *testing.T) {
	reset()

	actual, err := TestClient.GetSecrets("one")
	if err != nil {
		t.Error("Failed to obtain value: " + err.Error())
	}

	if actual["one"] != "uno" {
		t.Errorf("Failed to obtain the correct value. Expecting: '%s' , but got: '%s'", "uno", actual["one"])
	}
}

func TestSecretClient_GetSecrets(t *testing.T) {
	reset()

	actual, err := TestClient.GetSecrets("one", "two")
	if err != nil {
		t.Error("Failed to obtain value: " + err.Error())
	}

	if actual["one"] != "uno" {
		t.Errorf("Failed to obtain the correct value. Expecting: '%s' , but got: '%s'", "uno", actual["one"])
	}
	if actual["two"] != "dos" {
		t.Errorf("Failed to obtain the correct value. Expecting: '%s' , but got: '%s'", "uno", actual["two"])
	}
}

func TestSecretClient_SetSecret(t *testing.T) {
	reset()

	_ = TestClient.SetSecrets(map[string]string{"four": "vier"})
	actual, err := TestClient.GetSecrets("four")
	if err != nil {
		t.Error("Failed to obtain value: " + err.Error())
	}

	if actual["four"] != "vier" {
		t.Errorf("Failed to obtain the correct value. Expecting: '%s' , but got: '%s'", "vier", actual["four"])
	}
}

func TestSecretClient_SetSecrets(t *testing.T) {
	reset()

	_ = TestClient.SetSecrets(map[string]string{
		"one":  "ein",
		"four": "vier",
	})
	actual, err := TestClient.GetSecrets("one", "four")
	if err != nil {
		t.Error("Failed to obtain value: " + err.Error())
	}

	if actual["one"] != "ein" {
		t.Errorf("Failed to obtain the correct value. Expecting: '%s' , but got: '%s'", "ein", actual["one"])
	}
	if actual["four"] != "vier" {
		t.Errorf("Failed to obtain the correct value. Expecting: '%s' , but got: '%s'", "vier", actual["four"])
	}
}

func TestSecretClient_DeleteKey(t *testing.T) {
	reset()

	err := TestClient.DeleteKeys("one")
	if err != nil {
		t.Error("Unexpected error")
	}

	_, err = TestClient.GetSecrets("one")
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

func TestSecretClient_DeleteKeys(t *testing.T) {
	reset()

	err := TestClient.DeleteKeys("one", "two")
	if err != nil {
		t.Error("Unexpected error")
	}

	_, err = TestClient.GetSecrets("one", "two")
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
