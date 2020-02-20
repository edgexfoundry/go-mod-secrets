/*******************************************************************************
 * Copyright 2019 Dell Inc.
 * Copyright 2020 Intel Corp.
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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/edgexfoundry/go-mod-secrets/pkg"
)

const (
	lookupSelfVaultAPI = "/v1/auth/token/lookup-self"
	renewSelfVaultAPI  = "/v1/auth/token/renew-self"
)

// Client defines the behavior for interacting with the Vault REST secret key/value store via HTTP(S).
type Client struct {
	HttpConfig SecretConfig
	HttpCaller Caller

	// internal member variables
	lc      loggingClient
	context context.Context
}

func (c Client) refreshToken(ctx context.Context, tokenExpiredCallback tokenExpiredCallback) error {
	tokenData, err := c.getTokenLookupResponseData()

	if err != nil {
		return err
	}

	if !tokenData.Data.Renewable {
		// token is not renewable, log warning and return
		c.lc.Warn("token is not renewable from the secret store")
		return nil
	}

	// the renew interval is half of period value
	tokenPeriod := time.Duration(tokenData.Data.Period) * time.Second
	renewInterval := tokenPeriod / 2
	if renewInterval <= 0 {
		// no renew
		c.lc.Warn("no token renewal since renewInterval is 0")
		return nil
	}

	ttl := time.Duration(tokenData.Data.Ttl) * time.Second

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

func (c Client) doTokenRefreshPeriodically(renewInterval time.Duration,
	tokenExpiredCallback tokenExpiredCallback) {

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
					replacementToken, retry := tokenExpiredCallback(c.HttpConfig.Authentication.AuthToken)
					if !retry {
						ticker.Stop()
						return
					}
					c.HttpConfig.Authentication.AuthToken = replacementToken
				} else {
					// retry the renew calls upto retryAttempts
					addRetryAttempts := c.HttpConfig.AdditionalRetryAttempts
					// no retry
					if addRetryAttempts <= 0 {
						ticker.Stop()
						return
					}

					// do some retries
					// note the limit is 1 + additional retry attempts, cause we always need
					// to do the first try
					for tryNum := 1; err != nil && tryNum < 1+addRetryAttempts; tryNum++ {
						time.Sleep(c.HttpConfig.retryWaitPeriodTime)

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

func (c Client) getTokenLookupResponseData() (*TokenLookupResponse, error) {
	// call Vault's token self lookup API
	url := c.HttpConfig.BuildURL(lookupSelfVaultAPI)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set(AuthTypeHeader, c.HttpConfig.Authentication.AuthToken)

	resp, err := c.HttpCaller.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errHTTPResponse{
			statusCode: resp.StatusCode,
			errMsg:     "failed to lookup token",
		}
	}

	var result TokenLookupResponse
	jsonDec := json.NewDecoder(resp.Body)
	if jsonDec == nil {
		return nil, pkg.NewErrSecretStore("failed to obtain json decoder")
	}

	jsonDec.UseNumber()
	if err = jsonDec.Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c Client) renewToken() error {
	// call Vault's renew self API
	url := c.HttpConfig.BuildURL(renewSelfVaultAPI)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return err
	}

	req.Header.Set(AuthTypeHeader, c.HttpConfig.Authentication.AuthToken)

	resp, err := c.HttpCaller.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errHTTPResponse{
			statusCode: resp.StatusCode,
			errMsg:     "failed to renew token",
		}
	}

	c.lc.Debug("token is successfully renewed")
	return nil
}

// GetSecrets retrieves the secrets at the provided subpath that matches the specified keys.
func (c Client) GetSecrets(subPath string, keys ...string) (map[string]string, error) {
	data := make(map[string]string)
	var err error
	addRetryAttempts := c.HttpConfig.AdditionalRetryAttempts
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
			time.Sleep(c.HttpConfig.retryWaitPeriodTime)

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

// getAllKeys obtains all the keys that reside at the provided subpath.
func (c Client) getAllKeys(subPath string) (map[string]string, error) {
	url := c.HttpConfig.BuildSecretsPathURL() + subPath
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set(c.HttpConfig.Authentication.AuthType, c.HttpConfig.Authentication.AuthToken)

	if c.HttpConfig.Namespace != "" {
		req.Header.Set(NamespaceHeader, c.HttpConfig.Namespace)
	}

	resp, err := c.HttpCaller.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, pkg.NewErrSecretStore(fmt.Sprintf("Received a '%d' response from the secret store", resp.StatusCode))
	}

	defer resp.Body.Close()
	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	data, success := result["data"].(map[string]interface{})
	if !success || len(data) <= 0 {
		return nil, pkg.NewErrSecretStore(fmt.Sprintf("No secrets are present at the subpath: '%s'", subPath))
	}

	// Cast the secret values to strings
	secrets := make(map[string]string)
	for k, v := range data {
		secrets[k] = v.(string)
	}

	return secrets, nil
}

func isForbidden(err error) bool {
	if httpRespErr, ok := err.(errHTTPResponse); ok {
		return httpRespErr.statusCode == http.StatusForbidden
	}
	return false
}

// createHTTPClient creates and configures an HTTP client which can be used to communicate with the underlying
// secret-store based on the SecretConfig.
// Returns ErrCaRootCert is there is an error with the certificate.
func createHTTPClient(config SecretConfig) (Caller, error) {

	if config.RootCaCertPath == "" {
		return http.DefaultClient, nil
	}

	// Read and load the CA Root certificate so the client will be able to use TLS without skipping the verification of
	// the cert received by the server.
	caCert, err := ioutil.ReadFile(config.RootCaCertPath)
	if err != nil {
		return nil, ErrCaRootCert{
			path:        config.RootCaCertPath,
			description: err.Error(),
		}
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caCertPool,
				ServerName: config.ServerName,
			},
		},
	}, nil
}

// StoreSecrets stores the secrets at the provided subpath for the specified keys.
func (c Client) StoreSecrets(subPath string, secrets map[string]string) error {

	var err error
	addRetryAttempts := c.HttpConfig.AdditionalRetryAttempts
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
			time.Sleep(c.HttpConfig.retryWaitPeriodTime)

			err = c.store(subPath, secrets)
		}
	}

	return err
}

func (c Client) store(subPath string, secrets map[string]string) error {
	if len(secrets) == 0 {
		// nothing to store
		return nil
	}

	url := c.HttpConfig.BuildSecretsPathURL() + subPath

	payload, err := json.Marshal(secrets)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	req.Header.Set(c.HttpConfig.Authentication.AuthType, c.HttpConfig.Authentication.AuthToken)

	if c.HttpConfig.Namespace != "" {
		req.Header.Set(NamespaceHeader, c.HttpConfig.Namespace)
	}

	resp, err := c.HttpCaller.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if resp.Body != nil {
			resp.Body.Close()
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return pkg.NewErrSecretStore(fmt.Sprintf("Received a '%d' response from the secret store", resp.StatusCode))
	}

	return nil
}
