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

package vault

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/edgexfoundry/go-mod-secrets/pkg"
)

// Client defines the behavior for interacting with the Vault REST secret key/value store via HTTP(S).
type Client struct {
	HttpConfig SecretConfig
	HttpCaller Caller
}

// NewSecretClient constructs a SecretClient which communicates with Vault via HTTP(S)
func NewSecretClient(config SecretConfig) (pkg.SecretClient, error) {
	httpClient, err := createHTTPClient(config)
	if err != nil {
		return Client{}, err
	}

	if config.RetryWaitPeriod != "" {
		retryTimeDuration, err := time.ParseDuration(config.RetryWaitPeriod)
		if err != nil {
			return nil, err
		}
		config.retryWaitPeriodTime = retryTimeDuration
	}

	return Client{
		HttpConfig: config,
		HttpCaller: httpClient,
	}, nil

}

// GetSecrets retrieves the secrets at the provided path that match the specified keys.
func (c Client) GetSecrets(path string, keys ...string) (map[string]string, error) {
	data := make(map[string]string)
	var err error
	addRetryAttempts := c.HttpConfig.AdditionalRetryAttempts
	switch {
	case addRetryAttempts < 0:
		return nil, pkg.NewErrSecretStore(fmt.Sprintf("invalid retry attempts setting %d", addRetryAttempts))
	case addRetryAttempts == 0:
		// no retries
		data, err = c.getAllKeys(path)
		if err != nil {
			return nil, err
		}
	case addRetryAttempts > 0:
		// do some retries
		// note the limit is 1 + additional retry attempts, cause we always need
		// to do the first try
		data, err = c.getAllKeys(path)

		for tryNum := 1; err != nil && tryNum < 1+addRetryAttempts; tryNum++ {
			time.Sleep(c.HttpConfig.retryWaitPeriodTime)

			data, err = c.getAllKeys(path)
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

// getAllKeys obtains all the keys that reside at the provided path.
func (c Client) getAllKeys(path string) (map[string]string, error) {
	url := c.HttpConfig.BuildURL() + path
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
		return nil, pkg.NewErrSecretStore(fmt.Sprintf("No secrets are present at the path: '%s'", path))
	}

	// Cast the secret values to strings
	secrets := make(map[string]string)
	for k, v := range data {
		secrets[k] = v.(string)
	}

	return secrets, nil
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

func (c Client) StoreSecrets(path string, secrets map[string]string) error {

	var err error
	addRetryAttempts := c.HttpConfig.AdditionalRetryAttempts
	switch {
	case addRetryAttempts < 0:
		err = pkg.NewErrSecretStore(fmt.Sprintf("invalid retry attempts setting %d", addRetryAttempts))
	case addRetryAttempts == 0:
		// no retries
		err = c.store(path, secrets)
	case addRetryAttempts > 0:
		// do some retries
		// note the limit is 1 + additional retry attempts, cause we always need
		// to do the first try
		err = c.store(path, secrets)

		for tryNum := 1; err != nil && tryNum < 1+addRetryAttempts; tryNum++ {
			time.Sleep(c.HttpConfig.retryWaitPeriodTime)

			err = c.store(path, secrets)
		}
	}

	return err
}

func (c Client) store(path string, secrets map[string]string) error {
	if len(secrets) == 0 {
		// nothing to store
		return nil
	}

	url := c.HttpConfig.BuildURL() + path

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
