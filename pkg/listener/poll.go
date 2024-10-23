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
	"time"

	"github.com/edgexfoundry/go-mod-secrets/v4/secrets"
)

// InMemoryCacheListener handles retrieving and storing secrets from a secret store
// and provides updates based on a specified interval.
type InMemoryCacheListener struct {
	// secretClient retrieves secrets from a secret store.
	secretClient secrets.SecretClient
	// secretName contains the location of the secrets.
	secretName string
	// keys contains the keys for which to provide updates.
	keys []string
	// updaterChan communicates updates to the keys/
	updaterChan chan map[string]string
	// errorChan communicates errors from the background process to the caller.
	errorChan chan error
	// stopChan signals when the background process should begin shutting down.
	stopChan chan struct{}
	// backoffPattern contains a series of intervals to use when invoking the secret client.
	backoffPattern []int
	// cache stores the last known secrets
	cache map[string]string // Protect with mutex?
	// isRunning holds the state of the listener
	isRunning bool
	// timerFunc abstracts the logic used to create a timer. This is most useful for testing when validating the backoff pattern logic.
	timerFunc func(duration time.Duration) *time.Timer
	// runningStateMutex protects the 'isRunning' state of the listener from race conditions
	runningStateMutex *sync.Mutex
	// cacheMutex protects the 'cache' from race conditions.
	cacheMutex *sync.Mutex
}

// NewInMemoryCacheListener creates a new InMemoryCacheListener
func NewInMemoryCacheListener(client secrets.SecretClient, updateChan chan map[string]string, errorChan chan error, backoffPattern []int, path string, keys []string) InMemoryCacheListener {
	return InMemoryCacheListener{
		secretClient:      client,
		secretName:        path,
		keys:              keys,
		updaterChan:       updateChan,
		errorChan:         errorChan,
		stopChan:          make(chan struct{}, 10),
		backoffPattern:    backoffPattern,
		isRunning:         false,
		timerFunc:         time.NewTimer,
		runningStateMutex: &sync.Mutex{},
		cacheMutex:        &sync.Mutex{},
	}
}

// GetKeys retrieves the secrets via the secret client
func (c *InMemoryCacheListener) GetKeys() (map[string]string, error) {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	secrets, err := c.secretClient.GetSecret(c.secretName, c.keys...)
	if err != nil {
		return nil, err
	}

	c.cache = secrets

	return c.cache, nil
}

func (c *InMemoryCacheListener) SetSecrets(secrets map[string]string) error {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	if err := c.secretClient.StoreSecret(c.secretName, secrets); err != nil {
		return err
	}

	if c.cache == nil {
		c.cache = make(map[string]string)
	}

	for k, v := range secrets {
		c.cache[k] = v
	}

	keys := make([]string, 0, len(c.cache))
	for k := range c.cache {
		keys = append(keys, k)
	}
	c.keys = keys

	return nil
}

// Start invokes the background process which will provide updates.
func (c *InMemoryCacheListener) Start() error {
	c.runningStateMutex.Lock()
	defer c.runningStateMutex.Unlock()

	if c.isRunning {
		return ErrInvalidListenerState{message: "This listener has already started"}
	}

	c.isRunning = true
	go c.update()

	return nil
}

// Stop terminates the background process which provides updates.
func (c *InMemoryCacheListener) Stop() error {
	c.runningStateMutex.Lock()
	defer c.runningStateMutex.Unlock()

	if !c.isRunning {
		return ErrInvalidListenerState{message: "This listener has not been started"}
	}

	c.stopChan <- struct{}{}

	return nil
}

// update provides the logic for providing updates.
// This function is intended to be executed in a go-routine.
// **NOTE** The use of the 'stopChan' must be done in a thread safe manner since the result of receiving data from that
// channel will result in the 'InMemoryCacheListener.isRunning' to change state.
func (c *InMemoryCacheListener) update() {
	errorCount := 0
	for {
		backoffIndex := errorCount
		if backoffIndex > len(c.backoffPattern)-1 {
			backoffIndex = len(c.backoffPattern) - 1
		}

		timer := c.timerFunc(time.Duration(c.backoffPattern[backoffIndex]) * time.Second)
		select {
		case <-timer.C:
			// use anonymous function to implement a monitor around
			// Getsecrets and update of cache
			func() {
				c.cacheMutex.Lock()
				defer c.cacheMutex.Unlock()
				secrets, err := c.secretClient.GetSecret(c.secretName, c.keys...)
				if err != nil {
					c.errorChan <- err
					errorCount++
					return
				}

				errorCount = 0
				if c.cache == nil || !reflect.DeepEqual(secrets, c.cache) {
					c.cache = secrets
					c.updaterChan <- secrets
				}
			}()
		case <-c.stopChan:
			c.runningStateMutex.Lock()
			if !c.isRunning {
				c.errorChan <- ErrInvalidListenerState{message: "This listener has not been started"}
			}
			c.isRunning = false
			timer.Stop()
			c.runningStateMutex.Unlock()
			return
		}

	}
}
