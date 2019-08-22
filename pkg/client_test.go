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

var TestClient = SecretClient{
	Manager: MockSecretStoreManager{
		Secrets: map[string]string{
			"one":   "uno",
			"two":   "dos",
			"three": "tres",
		}}}

func reset() {
	TestClient = SecretClient{
		Manager: MockSecretStoreManager{
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

// MockSecretStoreManager a mock implementation of the SecretStoreManager which can be used for testing.
type MockSecretStoreManager struct {
	Secrets map[string]string
}

func (mssm MockSecretStoreManager) GetValues(keys ...string) (map[string]string, error) {
	data := mssm.Secrets

	values := make(map[string]string)
	var notFound []string
	for _, key := range keys {
		value, success := data[key]
		if !success {
			notFound = append(notFound, key)
			continue
		}

		values[key] = value
	}

	if len(notFound) > 0 {
		return nil, NewErrSecretsNotFound(notFound)
	}
	return values, nil
}
