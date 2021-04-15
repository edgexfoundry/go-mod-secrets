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

package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/edgexfoundry/go-mod-secrets/v2/pkg"
	"github.com/edgexfoundry/go-mod-secrets/v2/pkg/types"

	"github.com/edgexfoundry/go-mod-core-contracts/v2/clients/logger"
)

// a map variable to handle the case of the same caller to have
// multiple secret clients with potentially the same tokens while renewing token
// in the background go-routine
type vaultTokenToCancelFuncMap map[string]context.CancelFunc

// NewUserClient constructs a Vault *Client which communicates with Vault via HTTP(S) for basic usage of secrets
//
// ctx is the background context that can be used to cancel or cleanup
// the background process when it is no longer needed
//
// lc is any logging client that implements the loggingClient interface;
// today EdgeX's logger.LoggingClient from go-mod-core-contracts satisfies this implementation
//
// tokenExpiredCallback is the callback function dealing with the expired token
// and getting a replacement token
// it can be nil if the caller choose not to do that
func NewSecretsClient(ctx context.Context, config types.SecretConfig, lc logger.LoggingClient, callback pkg.TokenExpiredCallback) (*Client, error) {
	vaultClient, err := NewClient(config, nil, true, lc)
	if err != nil {
		return nil, err
	}

	// tokenCancelFunc is an internal map with token as key and
	// the context.cancel function as value
	tokenCancelFunc := make(vaultTokenToCancelFuncMap)

	// mapMutex protects the internal map cache from race conditions
	mapMutex := &sync.Mutex{}
	mapMutex.Lock()

	// if there is context already associated with the given token,
	// then we cancel it first
	if cancel, exists := tokenCancelFunc[config.Authentication.AuthToken]; exists {
		cancel()
	}

	mapMutex.Unlock()

	cCtx, cancel := context.WithCancel(ctx)
	if err = vaultClient.refreshToken(cCtx, callback); err != nil {
		cancel()
		mapMutex.Lock()
		delete(tokenCancelFunc, config.Authentication.AuthToken)
		mapMutex.Unlock()
	} else {
		mapMutex.Lock()
		tokenCancelFunc[config.Authentication.AuthToken] = cancel
		mapMutex.Unlock()
	}

	return vaultClient, err
}

// GetSecrets retrieves the secrets at the provided sub-path that matches the specified keys.
func (c *Client) GetSecrets(subPath string, keys ...string) (map[string]string, error) {
	data := make(map[string]string)
	var err error
	addRetryAttempts := c.Config.AdditionalRetryAttempts
	switch {
	case addRetryAttempts < 0:
		return nil, pkg.NewErrSecretStore(fmt.Sprintf("invalid retry attempts setting %d", addRetryAttempts))
	case addRetryAttempts == 0:
		// no retries
		data, err = c.getAllKeys(subPath)
		if err != nil {
			return nil, err
		}
	case addRetryAttempts > 0:
		// do some retries
		// note the limit is 1 + additional retry attempts, cause we always need
		// to do the first try
		data, err = c.getAllKeys(subPath)

		for tryNum := 1; err != nil && tryNum < 1+addRetryAttempts; tryNum++ {
			time.Sleep(c.Config.RetryWaitPeriodTime)

			data, err = c.getAllKeys(subPath)
		}

		// since we finished the above loop, then check if the last iteration
		// failed
		if err != nil {
			return nil, err
		}
	}

	// Do not filter any of the secrets
	if len(keys) <= 0 {
		return data, nil
	}

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
		return nil, pkg.NewErrSecretsNotFound(notFound)
	}

	return values, nil
}

// StoreSecrets stores the secrets at the provided sub-path for the specified keys.
func (c *Client) StoreSecrets(subPath string, secrets map[string]string) error {

	var err error
	addRetryAttempts := c.Config.AdditionalRetryAttempts
	switch {
	case addRetryAttempts < 0:
		err = pkg.NewErrSecretStore(fmt.Sprintf("invalid retry attempts setting %d", addRetryAttempts))
	case addRetryAttempts == 0:
		// no retries
		err = c.store(subPath, secrets)
	case addRetryAttempts > 0:
		// do some retries
		// note the limit is 1 + additional retry attempts, cause we always need
		// to do the first try
		err = c.store(subPath, secrets)

		for tryNum := 1; err != nil && tryNum < 1+addRetryAttempts; tryNum++ {
			time.Sleep(c.Config.RetryWaitPeriodTime)

			err = c.store(subPath, secrets)
		}
	}

	return err
}

// GenerateConsulToken generates a new Consul token using serviceKey as role name to
// call secretstore's consul/creds API
// the serviceKey is used in the part of secretstore's URL as role name and should be accessible to the API
func (c *Client) GenerateConsulToken(serviceKey string) (string, error) {
	trimmedSrvKey := strings.TrimSpace(serviceKey)
	if len(trimmedSrvKey) == 0 {
		return emptyToken, pkg.NewErrSecretStore("serviceKey cannot be empty for generating Consul token")
	}

	if len(c.Config.Authentication.AuthToken) == 0 {
		return emptyToken, pkg.NewErrSecretStore("secretestore token from config cannot be empty for generating Consul token")
	}

	credsURL, err := c.Config.BuildURL(fmt.Sprintf(GenerateConsulTokenAPI, trimmedSrvKey))
	if err != nil {
		return emptyToken, err
	}

	req, err := http.NewRequest(http.MethodGet, credsURL, http.NoBody)
	if err != nil {
		return emptyToken, err
	}

	req.Header.Set(AuthTypeHeader, c.Config.Authentication.AuthToken)

	resp, err := c.HttpCaller.Do(req)
	if err != nil {
		return emptyToken, err
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	tokenResp, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return emptyToken, err
	}

	if resp.StatusCode != http.StatusOK {
		return emptyToken, ErrHTTPResponse{
			StatusCode: resp.StatusCode,
			ErrMsg:     fmt.Sprintf("failed to generate Consul token using [%s]: %s", trimmedSrvKey, string(tokenResp)),
		}
	}

	type TokenResp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	var consulTokenResp TokenResp
	if err := json.NewDecoder(bytes.NewReader(tokenResp)).Decode(&consulTokenResp); err != nil {
		return emptyToken, err
	}

	c.lc.Infof("successfully generated Consul token for service %s", serviceKey)

	return consulTokenResp.Data.Token, nil
}

func (c *Client) getTokenDetails() (*types.TokenMetadata, error) {
	// call Vault's token self lookup API
	url, err := c.Config.BuildURL(lookupSelfVaultAPI)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set(AuthTypeHeader, c.Config.Authentication.AuthToken)

	resp, err := c.HttpCaller.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrHTTPResponse{
			StatusCode: resp.StatusCode,
			ErrMsg:     "failed to lookup token",
		}
	}

	// the returned JSON structure for token self-read is TokenLookupResponse
	result := TokenLookupResponse{}
	jsonDec := json.NewDecoder(resp.Body)
	if jsonDec == nil {
		return nil, pkg.NewErrSecretStore("failed to obtain json decoder")
	}

	jsonDec.UseNumber()
	if err = jsonDec.Decode(&result); err != nil {
		return nil, err
	}

	return &result.Data, nil
}

func (c *Client) refreshToken(ctx context.Context, tokenExpiredCallback pkg.TokenExpiredCallback) error {
	tokenData, err := c.getTokenDetails()

	if err != nil {
		return err
	}

	if !tokenData.Renewable {
		// token is not renewable, log warning and return
		c.lc.Warn("token is not renewable from the secret store")
		return nil
	}

	// the renew interval is half of period value
	tokenPeriod := time.Duration(tokenData.Period) * time.Second
	renewInterval := tokenPeriod / 2
	if renewInterval <= 0 {
		// cannot renew, as the renew interval is non-positive
		c.lc.Warn("no token renewal since renewInterval is 0")
		return nil
	}

	ttl := time.Duration(tokenData.Ttl) * time.Second

	// if the current time-to-live is already less than the half of period
	// need to renew the token right away
	if ttl <= renewInterval {
		// call renew self api
		c.lc.Info("ttl already <= half of the renewal period")
		if err := c.renewToken(); err != nil {
			return err
		}
	}

	c.context = ctx

	// goroutine to periodically renew the service token based on renewInterval
	go c.doTokenRefreshPeriodically(renewInterval, tokenExpiredCallback)

	return nil
}

func (c *Client) doTokenRefreshPeriodically(renewInterval time.Duration,
	tokenExpiredCallback pkg.TokenExpiredCallback) {
	c.lc.Infof("kick off token renewal with interval: %v", renewInterval)

	ticker := time.NewTicker(renewInterval)
	for {
		select {

		case <-c.context.Done():
			ticker.Stop()
			c.lc.Info("context cancelled, dismiss the token renewal process")
			return

		case <-ticker.C:
			// renew token to keep it refreshed
			// if err happens then handle it according to the callback func tokenExpiredCallback
			if err := c.renewToken(); err != nil {
				if isForbidden(err) {
					// the current token is expired,
					// cannot renew, handle it based upon
					// the implementation of callback from the caller if any
					if tokenExpiredCallback == nil {
						ticker.Stop()
						return
					}
					replacementToken, retry := tokenExpiredCallback(c.Config.Authentication.AuthToken)
					if !retry {
						ticker.Stop()
						return
					}
					c.Config.Authentication.AuthToken = replacementToken
				} else {
					// retry the renew calls upto retryAttempts
					addRetryAttempts := c.Config.AdditionalRetryAttempts
					// no retry
					if addRetryAttempts <= 0 {
						ticker.Stop()
						return
					}

					// do some retries
					// note the limit is 1 + additional retry attempts, cause we always need
					// to do the first try
					for tryNum := 1; err != nil && tryNum < 1+addRetryAttempts; tryNum++ {
						time.Sleep(c.Config.RetryWaitPeriodTime)

						err = c.renewToken()
					}

					// since we finished the above loop,
					// then check if the last iteration failed
					if err != nil {
						ticker.Stop()
						return
					}
				}
			}
		}
	}
}

func (c *Client) renewToken() error {
	// call Vault's renew self API
	url, err := c.Config.BuildURL(renewSelfVaultAPI)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return err
	}

	req.Header.Set(AuthTypeHeader, c.Config.Authentication.AuthToken)

	resp, err := c.HttpCaller.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return ErrHTTPResponse{
			StatusCode: resp.StatusCode,
			ErrMsg:     "failed to renew token",
		}
	}

	c.lc.Debug("token is successfully renewed")
	return nil
}

// getAllKeys obtains all the keys that reside at the provided sub-path.
func (c *Client) getAllKeys(subPath string) (map[string]string, error) {
	url, err := c.Config.BuildSecretsPathURL(subPath)
	if err != nil {
		return nil, err
	}

	c.lc.Debug(fmt.Sprintf("Using Secrets URL of `%s`", url))

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set(c.Config.Authentication.AuthType, c.Config.Authentication.AuthToken)

	if c.Config.Namespace != "" {
		req.Header.Set(NamespaceHeader, c.Config.Namespace)
	}

	resp, err := c.HttpCaller.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, pkg.NewErrSecretStore(fmt.Sprintf("Received a '%d' response from the secret store", resp.StatusCode))
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	data, success := result["data"].(map[string]interface{})
	if !success || len(data) <= 0 {
		return nil, pkg.NewErrSecretStore(fmt.Sprintf("No secretKeyValues are present at the subpath: '%s'", subPath))
	}

	// Cast the secret values to strings
	secretKeyValues := make(map[string]string)
	for k, v := range data {
		secretKeyValues[k] = v.(string)
	}

	return secretKeyValues, nil
}

func isForbidden(err error) bool {
	if httpRespErr, ok := err.(ErrHTTPResponse); ok {
		return httpRespErr.StatusCode == http.StatusForbidden
	}
	return false
}

func (c *Client) store(subPath string, secrets map[string]string) error {
	if len(secrets) == 0 {
		// nothing to store
		return nil
	}

	url, err := c.Config.BuildSecretsPathURL(subPath)
	if err != nil {
		return err
	}

	c.lc.Debug(fmt.Sprintf("Using Secrets URL of `%s`", url))

	payload, err := json.Marshal(secrets)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	req.Header.Set(c.Config.Authentication.AuthType, c.Config.Authentication.AuthToken)

	if c.Config.Namespace != "" {
		req.Header.Set(NamespaceHeader, c.Config.Namespace)
	}

	resp, err := c.HttpCaller.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return pkg.NewErrSecretStore(fmt.Sprintf("Received a '%d' response from the secret store", resp.StatusCode))
	}

	return nil
}
