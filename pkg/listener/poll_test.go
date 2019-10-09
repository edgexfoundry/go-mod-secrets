/********************************************************************************
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

package listener

import (
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/edgexfoundry/go-mod-secrets/pkg"
)

var Secrets = map[string]string{
	"one":   "uno",
	"two":   "dos",
	"three": "tres",
}

var TestPath = "/data"
var TestClient = pkg.SecretClient{
	Manager: MockSecretStoreManager{
		secretStore: &Secrets,
	}}

type MockSecretStoreManager struct {
	secretStore *map[string]string
}

func (mssm MockSecretStoreManager) GetValues(path string, keys ...string) (map[string]string, error) {
	if path != TestPath {
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

func TestGetKeys(t *testing.T) {
	tests := []struct {
		name              string
		client            pkg.SecretClient
		path              string
		keys              []string
		expectedResult    map[string]string
		expectError       bool
		expectedErrorType error
	}{
		{
			name:              "Get keys",
			client:            TestClient,
			path:              TestPath,
			keys:              []string{"one", "two"},
			expectedResult:    map[string]string{"one": "uno", "two": "dos"},
			expectError:       false,
			expectedErrorType: nil,
		},
		{
			name:              "Get keys from unknown path",
			client:            TestClient,
			path:              "/unknownpath",
			keys:              []string{"one", "two"},
			expectedResult:    nil,
			expectError:       true,
			expectedErrorType: pkg.ErrSecretsNotFound{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := NewInMemoryCacheListener(test.client, make(chan map[string]string), make(chan error), []int{0}, test.path, test.keys)
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

func TestGetKeysError(t *testing.T) {
	c := NewInMemoryCacheListener(TestClient, make(chan map[string]string), make(chan error, 10), []int{0}, TestPath, []string{"doesNotExist"})
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
	errChan := make(chan error)
	c := NewInMemoryCacheListener(TestClient, make(chan map[string]string), errChan, []int{0}, TestPath, []string{"doesNotExist"})

	err := c.Start()
	if err != nil {
		t.Errorf("Unexpected error ocurred: %s", err.Error())
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
	c := NewInMemoryCacheListener(TestClient, make(chan map[string]string), make(chan error), []int{0}, TestPath, []string{"one"})
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
	c := NewInMemoryCacheListener(TestClient, make(chan map[string]string), make(chan error), []int{0}, TestPath, []string{"one"})
	err := c.Start()
	if err != nil {
		t.Errorf("Unexpected error ocurred: %s", err.Error())
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

	errChan := make(chan error)
	updateChan := make(chan map[string]string)
	c := NewInMemoryCacheListener(TestClient, updateChan, errChan, []int{0}, TestPath, []string{"one", "two"})
	_, err := c.GetKeys()
	if err != nil {
		t.Errorf("Unexpected error ocurred: %s", err.Error())
		return
	}

	err = c.Start()
	if err != nil {
		t.Errorf("Unexpected error ocurred: %s", err.Error())
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

	callCount := 0
	backoffPattern := []int{1, 2, 3}
	numOfTries := len(backoffPattern) + 1

	completeChan := make(chan struct{})
	c := NewInMemoryCacheListener(TestClient, make(chan map[string]string), make(chan error, 10), backoffPattern, TestPath, []string{"doesNotExist"})

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
		t.Errorf("Unexpected error ocurred: %s", err.Error())
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

	numOfRestarts := 1000
	c := NewInMemoryCacheListener(TestClient, make(chan map[string]string), make(chan error), []int{0}, TestPath, []string{"one"})

	// Create 2 go-routines which will restart the listener concurrently to test the thread-safety of the state
	// modifications.
	wg := sync.WaitGroup{}
	wg.Add(1)
	go restart(c, numOfRestarts, &wg, t)
	wg.Add(1)
	go restart(c, numOfRestarts, &wg, t)
	wg.Wait()
}

// restart executes restart functionality on the listener repeatedly.
// This is a helper function used to aid in testing the state handling functionality. This function ignores errors
// returned by calling any start, stop, or restart function since errors are expected to be returned to the caller
// during an invalid state issue. This is expected to run in a go-routine.
func restart(c InMemoryCacheListener, numOfRestarts int, wg *sync.WaitGroup, t *testing.T) {
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
