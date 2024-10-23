/********************************************************************************
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

package listener

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/edgexfoundry/go-mod-secrets/v4/pkg"
	"github.com/edgexfoundry/go-mod-secrets/v4/pkg/types"
	"github.com/edgexfoundry/go-mod-secrets/v4/secrets"
)

const (
	// define as constants to avoid using global variables as global variables are evil to the whole package level scope:
	// Global variables can cause side effects which are difficult to keep track of. A code in one function may
	// change the variables state while another unrelated chunk of code may be affected by it.
	testSecretName = "data"
)

func newTestMockSecretClient() MockSecretClient {
	secrets := getTestSecrets()
	return MockSecretClient{secretStore: &secrets}
}

func getTestSecrets() map[string]string {
	return map[string]string{
		"one":   "uno",
		"two":   "dos",
		"three": "tres",
	}
}

type MockSecretClient struct {
	secretStore *map[string]string
}

func (mssm MockSecretClient) GetSecret(secretName string, keys ...string) (map[string]string, error) {
	if secretName != testSecretName {
		return nil, pkg.NewErrSecretsNotFound(keys)
	}

	var notFound []string
	secrets := make(map[string]string)
	for _, key := range keys {
		ss := *mssm.secretStore
		s, ok := ss[key]
		if !ok {
			notFound = append(notFound, key)
			continue
		}
		secrets[key] = s
	}

	if len(notFound) > 0 {
		return nil, pkg.NewErrSecretsNotFound(notFound)
	}

	return secrets, nil
}

func (mssm MockSecretClient) StoreSecret(secretName string, secrets map[string]string) error {
	if secretName != testSecretName {
		return pkg.NewErrSecretStore(fmt.Sprintf("incorrect secretName for storing secrets: %s", secretName))
	}

	// sanity check before store secrets
	for key := range secrets {
		// empty key is not allowed
		if strings.TrimSpace(key) == "" {
			return pkg.NewErrSecretStore("cannot store secrets with empty key")
		}
	}

	// now we are ready to store good secrets
	ss := *mssm.secretStore
	for key, value := range secrets {
		ss[key] = value
	}
	return nil
}

func (mssm MockSecretClient) GetSecretNames() ([]string, error) {
	return nil, nil
}

func (mssm MockSecretClient) GetTokenDetails() (*types.TokenMetadata, error) {
	return nil, nil
}

func (mssm MockSecretClient) SetAuthToken(_ context.Context, _ string) error {
	panic("SetAuthToken not implemented")
}

func (mssm MockSecretClient) GetSelfJWT(_ string) (string, error) {
	panic("GetSelfJWT not implemented")
}

func (mssm MockSecretClient) IsJWTValid(_ string) (bool, error) {
	panic("IsJWTValid not implemented")
}

func TestGetKeys(t *testing.T) {
	testClient := newTestMockSecretClient()
	tests := []struct {
		name              string
		client            secrets.SecretClient
		secretName        string
		keys              []string
		expectedResult    map[string]string
		expectError       bool
		expectedErrorType error
	}{
		{
			name:              "Get keys",
			client:            testClient,
			secretName:        testSecretName,
			keys:              []string{"one", "two"},
			expectedResult:    map[string]string{"one": "uno", "two": "dos"},
			expectError:       false,
			expectedErrorType: nil,
		},
		{
			name:              "Get keys from unknown secretName",
			client:            testClient,
			secretName:        "unknownsecretName",
			keys:              []string{"one", "two"},
			expectedResult:    nil,
			expectError:       true,
			expectedErrorType: pkg.ErrSecretsNotFound{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := NewInMemoryCacheListener(test.client, make(chan map[string]string), make(chan error), []int{0}, test.secretName, test.keys)
			actual, err := c.GetKeys()

			if test.expectError && err == nil {
				t.Error("Expected an error")
				return
			}

			if !test.expectError && err != nil {
				t.Errorf("Unexpectedly encountered error: %s", err.Error())
				return
			}

			if test.expectError && test.expectedErrorType != nil {
				eet := reflect.TypeOf(test.expectedErrorType)
				aet := reflect.TypeOf(err)
				if !aet.AssignableTo(eet) {
					t.Errorf("Expected error of type %v, but got an error of type %v", eet, aet)
				}
				return
			}

			if !reflect.DeepEqual(test.expectedResult, actual) {
				t.Errorf("Expected result does not match the observed.\nExpected: %v\nObserved: %v\n", test.expectedResult, actual)
				return
			}

		})
	}
}

func TestStoreSecrets(t *testing.T) {
	testClient := newTestMockSecretClient()
	tests := []struct {
		name              string
		client            secrets.SecretClient
		secretName        string
		secrets           map[string]string
		expectedResult    map[string]string
		expectError       bool
		expectedErrorType error
	}{
		{
			name:              "Store one secret",
			client:            testClient,
			secretName:        testSecretName,
			secrets:           map[string]string{"one": "uno"},
			expectedResult:    map[string]string{"one": "uno"},
			expectError:       false,
			expectedErrorType: nil,
		},
		{
			name:              "Store secrets",
			client:            testClient,
			secretName:        testSecretName,
			secrets:           map[string]string{"one": "uno", "two": "dos"},
			expectedResult:    map[string]string{"one": "uno", "two": "dos"},
			expectError:       false,
			expectedErrorType: nil,
		},
		{
			name:              "Store secrets from unknown secretName",
			client:            testClient,
			secretName:        "unknownsecretName",
			secrets:           map[string]string{"one": "uno", "two": "dos"},
			expectedResult:    nil,
			expectError:       true,
			expectedErrorType: pkg.NewErrSecretStore("incorrect secretName for storing secrets: unknownsecretName"),
		},
		{
			name:              "Store one invalid empty key of secret",
			client:            testClient,
			secretName:        testSecretName,
			secrets:           map[string]string{"": "empty"},
			expectedResult:    nil,
			expectError:       true,
			expectedErrorType: pkg.NewErrSecretStore("cannot store secrets with empty key"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := NewInMemoryCacheListener(test.client, make(chan map[string]string), make(chan error), []int{0}, test.secretName, nil)
			err := c.SetSecrets(test.secrets)

			if test.expectError && err == nil {
				t.Error("Expected an error")
				return
			}

			if !test.expectError && err != nil {
				t.Errorf("Unexpectedly encountered error: %s", err.Error())
				return
			}

			if test.expectError && test.expectedErrorType != nil {
				eet := reflect.TypeOf(test.expectedErrorType)
				aet := reflect.TypeOf(err)
				if !aet.AssignableTo(eet) {
					t.Errorf("Expected error of type %v, but got an error of type %v", eet, aet)
				}
				return
			}

			// then retrieve to see if secrets got stored
			actual, _ := c.GetKeys()
			if !reflect.DeepEqual(test.expectedResult, actual) {
				t.Errorf("Expected result does not match the observed.\nExpected: %v\nObserved: %v\n", test.expectedResult, actual)
				return
			}

		})
	}
}

func TestGetKeysError(t *testing.T) {
	testClient := newTestMockSecretClient()
	c := NewInMemoryCacheListener(testClient, make(chan map[string]string), make(chan error, 10), []int{0}, testSecretName, []string{"doesNotExist"})
	_, err := c.GetKeys()
	if err == nil {
		t.Errorf("Expected an error")
		return
	}

	switch err.(type) {
	case pkg.ErrSecretsNotFound:
		break
	default:
		t.Errorf("Expected error of type ErrSecretsNotFound")
	}
}

func TestErrorPropagation(t *testing.T) {
	testClient := newTestMockSecretClient()
	errChan := make(chan error)
	c := NewInMemoryCacheListener(testClient, make(chan map[string]string), errChan, []int{0}, testSecretName, []string{"doesNotExist"})

	err := c.Start()
	if err != nil {
		t.Errorf("Unexpected error occurred: %s", err.Error())
		return
	}
	timeout := time.NewTimer(500 * time.Millisecond)
	select {
	case <-errChan:
		break
	case <-timeout.C:
		t.Errorf("Failed to communicate error within the given timeframe")
	}
}

func TestStopStateCheck(t *testing.T) {
	testClient := newTestMockSecretClient()
	c := NewInMemoryCacheListener(testClient, make(chan map[string]string), make(chan error), []int{0}, testSecretName, []string{"one"})
	err := c.Stop()
	if err == nil {
		t.Errorf("Expected error for invalid state")
		return
	}

	switch err.(type) {
	case ErrInvalidListenerState:
		break
	default:
		t.Errorf("Expected error of type ErrInvalidListenerState")
	}
}

func TestStartStateCheck(t *testing.T) {
	testClient := newTestMockSecretClient()
	c := NewInMemoryCacheListener(testClient, make(chan map[string]string), make(chan error), []int{0}, testSecretName, []string{"one"})
	err := c.Start()
	if err != nil {
		t.Errorf("Unexpected error occurred: %s", err.Error())
		return
	}

	err = c.Start()
	if err == nil {
		t.Errorf("Expected error for invalid state")
		return
	}

	switch err.(type) {
	case ErrInvalidListenerState:
		break
	default:
		t.Errorf("Expected error of type ErrInvalidListenerState")
	}
}

/*
 / Tests which are run in parallel
*/

func TestNoUpdate(t *testing.T) {
	// Run this test in parallel with with other tests that have a timeout.
	t.Parallel()

	testClient := newTestMockSecretClient()
	errChan := make(chan error)
	updateChan := make(chan map[string]string)
	c := NewInMemoryCacheListener(testClient, updateChan, errChan, []int{0}, testSecretName, []string{"one", "two"})
	_, err := c.GetKeys()
	if err != nil {
		t.Errorf("Unexpected error occurred: %s", err.Error())
		return
	}

	err = c.Start()
	if err != nil {
		t.Errorf("Unexpected error occurred: %s", err.Error())
		return
	}
	timeout := time.NewTimer(3 * time.Second)
	select {
	case <-updateChan:
		t.Errorf("Expected no updates, but got one")
	case <-errChan:
		t.Errorf("Expected no errors, but got one")
	case <-timeout.C:
		break
	}
}

func TestBackoffPattern(t *testing.T) {
	// Run this test in parallel with with other tests that have a timeout.
	t.Parallel()

	testClient := newTestMockSecretClient()
	callCount := 0
	backoffPattern := []int{1, 2, 3}
	numOfTries := len(backoffPattern) + 1

	completeChan := make(chan struct{})
	c := NewInMemoryCacheListener(testClient, make(chan map[string]string), make(chan error, 10), backoffPattern, testSecretName, []string{"doesNotExist"})

	// Warp the Timer constructor with some verification logic so we can validate that the underlying timer is being
	// invoked with the correct intervals.
	c.timerFunc = func(duration time.Duration) *time.Timer {
		if callCount >= numOfTries {
			completeChan <- struct{}{}
		}

		index := callCount
		if index > len(backoffPattern)-1 {
			index = len(backoffPattern) - 1
		}

		expected := time.Duration(backoffPattern[index]) * time.Second

		if expected != duration {
			t.Errorf("Expected: %v, and instead got: %v", expected, duration)
		}

		callCount++
		return time.NewTimer(duration)
	}

	err := c.Start()
	if err != nil {
		t.Errorf("Unexpected error occurred: %s", err.Error())
		return
	}

	timeout := time.NewTimer(30 * time.Second)
	select {
	case <-completeChan:
		_ = c.Stop()
		break
	case <-timeout.C:
		t.Errorf("Failed to communicate error within the given timeframe")
	}
}

// TestStateConcurrency tests the handling of the state within the listener.
// This test concurrently start and stops the listener in an attempt to trigger a deadlock or race condition. This test
// should be run with the '-race' option enabled to leverage the Go race detection tools.
func TestStateConcurrency(t *testing.T) {
	// Run this test in parallel with with other tests that may take longer to execute.
	t.Parallel()

	testClient := newTestMockSecretClient()

	numOfRestarts := 600
	c := NewInMemoryCacheListener(testClient, make(chan map[string]string), make(chan error), []int{0}, testSecretName, []string{"one"})

	// Create 2 go-routines which will restart the listener concurrently to test the thread-safety of the state
	// modifications.
	wg := sync.WaitGroup{}
	wg.Add(1)
	go restart(c, numOfRestarts, &wg)
	wg.Add(1)
	go restart(c, numOfRestarts, &wg)
	wg.Wait()
}

// restart executes restart functionality on the listener repeatedly.
// This is a helper function used to aid in testing the state handling functionality. This function ignores errors
// returned by calling any start, stop, or restart function since errors are expected to be returned to the caller
// during an invalid state issue. This is expected to run in a go-routine.
func restart(c InMemoryCacheListener, numOfRestarts int, wg *sync.WaitGroup) {
	defer wg.Done()
	for i := 0; i < numOfRestarts; i++ {
		err := c.Start()
		if err != nil {
			continue
		}

		err = c.Stop()
		if err != nil {
			continue
		}
	}
}
