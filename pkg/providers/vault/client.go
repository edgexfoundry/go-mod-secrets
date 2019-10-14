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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/edgexfoundry/go-mod-secrets/pkg"
)

// Client defines the behavior for interacting with the Vault REST secret key/value store via HTTP(S).
type Client struct {
	HttpConfig SecretConfig
	HttpCaller Caller
}

// NewSecretClient constructs a SecretClient which communicates with Vault via HTTP(S)
func NewSecretClient(config SecretConfig) (pkg.SecretClient, error) {
	httpClient, err := createHttpClient(config)
	if err != nil {
		return Client{}, err
	}

	return Client{
		HttpConfig: config,
		HttpCaller: httpClient,
	}, nil

}

// GetValues retrieves the secrets at the provided path that match the specified keys.
func (c Client) GetSecrets(path string, keys ...string) (map[string]string, error) {
	data, err := c.getAllKeys(path)
	if err != nil {
		return nil, err
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

// createHttpClient creates and configures an HTTP client which can be used to communicate with the underlying
// secret-store based on the SecretConfig.
// Returns ErrCaRootCert is there is an error with the certificate.
func createHttpClient(config SecretConfig) (Caller, error) {

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
