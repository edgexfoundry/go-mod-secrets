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

package pkg

type SecretStoreManager interface {
	// GetValue Retrieves the values associated with the specified keys
	// returns ErrSecretNotFound if no value is associated with the key
	GetValues(keys ...string) (map[string]string, error)

	// SetKeyValue Sets the values associated with the specified keys
	SetKeyValues(secrets map[string]string) error

	// DeleteKeyValue Deletes the values associated with the specified keys
	DeleteKeyValues(keys ...string) error
}
