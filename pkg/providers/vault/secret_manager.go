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

// HttpSecretStoreManager defines the behavior for interacting with the Vault REST secret key/value store via HTTP.
type HttpSecretStoreManager struct {
	HttpConfig SecretConfig
	HttpCaller Caller
}

// NewSecretClient constructs a SecretClient which communicates with Vault via HTTP
func NewSecretClient(config SecretConfig) (pkg.SecretClient, error) {
	httpClient, err := createHttpClient(config)
	if err != nil {
		return pkg.SecretClient{}, err
	}

	return pkg.SecretClient{
		Manager: HttpSecretStoreManager{
			HttpConfig: config,
			HttpCaller: httpClient,
		},
	}, nil

}

func (c HttpSecretStoreManager) GetValues(keys ...string) (map[string]string, error) {
	data, err := c.getAllKeys()
	if err != nil {
		return nil, err
	}

	values := make(map[string]string)
	var notFound []string

	for _, key := range keys {
		value, success := data[key].(string)
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

func (c HttpSecretStoreManager) getAllKeys() (map[string]interface{}, error) {
	req, err := http.NewRequest(http.MethodGet, c.HttpConfig.BuildURL(), nil)
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
	if !success {
		err = fmt.Errorf("no data retrieved from secrets service")
		return nil, err
	}

	return data, nil
}

// createHttpClient creates and configures an HTTP client which can be used to communicate with the underlying
// secret-store based on the SecretConfig.
// Returns ErrCaRootCert is there is an error with the certificate.
func createHttpClient(config SecretConfig) (Caller, error) {

	if config.RootCaCert == "" {
		return http.DefaultClient, nil
	}

	// Read and load the CA Root certificate so the client will be able to use TLS without skipping the verification of
	// the cert received by the server.
	caCert, err := ioutil.ReadFile(config.RootCaCert)
	if err != nil {
		return nil, ErrCaRootCert{
			path:        config.RootCaCert,
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
