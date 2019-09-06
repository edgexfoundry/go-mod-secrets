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
// Package errors contains the error types which are used by the SecretClient to communicate errors
package pkg

import (
	"fmt"
	"strings"
)

// ErrSecretStoreConn error for communication errors with the underlying storage mechanism
type ErrSecretStoreConn struct{}

func (ErrSecretStoreConn) Error() string {
	return "Unable to obtain from underlying data-store"
}

// ErrSecretsNotFound error when a secret cannot be found. This aids in differentiating between empty("") values and non-existent keys
type ErrSecretsNotFound struct {
	keys []string
}

func (scnf ErrSecretsNotFound) Error() string {
	return fmt.Sprintf("No value for the keys: [%s] exists", strings.Join(scnf.keys, ","))
}

// NewErrSecretsNotFound creates a new ErrSecretsNotFound error.
func NewErrSecretsNotFound(keys []string) ErrSecretsNotFound {
	return ErrSecretsNotFound{keys: keys}
}
