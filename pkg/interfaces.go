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

// SecretStoreManager provides functionality for interacting with an underlying data-store.
type SecretStoreManager interface {
	// GetValue retrieves the values associated with the specified keys and path. If no keys are specified then all of
	// the keys associated with the path will be returned.
	// returns ErrSecretsNotFound if any of the specified keys do not have a value set.
	GetValues(path string, keys ...string) (map[string]string, error)
}
