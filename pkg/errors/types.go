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
package errors

import "fmt"

// ErrSecretStoreConn error for communication errors with the underlying storage mechanism
type ErrSecretStoreConn struct{}

func (ErrSecretStoreConn) Error() string {
	return "Unable to obtain from underlying data-store"
}

// ErrSecretNotFound error when a secret cannot be found. This aids in differentiating between empty("") values and non-existent keys
type ErrSecretNotFound struct {
	Key string
}

func (scnf ErrSecretNotFound) Error() string {
	return fmt.Sprintf("No value for the key: '%s' exists", scnf.Key)
}

// ErrUnsupportedValue error for unsupported data such as invalid characters or the length of key/values
type ErrUnsupportedValue struct{}

func (ErrUnsupportedValue) Error() string {
	panic("implement me")
}
