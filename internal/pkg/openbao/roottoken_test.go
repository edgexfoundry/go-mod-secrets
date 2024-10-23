//
// Copyright (c) 2021 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.
//

package openbao

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"
	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func TestRegenRootToken(t *testing.T) {
	// Arrange
	mockLogger := logger.NewMockClient()

	requestNumber := 0

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestNumber++
		theMethod := r.Method
		thePath := r.URL.EscapedPath()
		switch requestNumber {
		case 1:
			assert.Equal(t, "DELETE", theMethod)
			assert.Equal(t, RootTokenControlAPI, thePath)
			w.WriteHeader(http.StatusNoContent)
		case 2:
			assert.Equal(t, "PUT", theMethod)
			assert.Equal(t, RootTokenControlAPI, thePath)
			w.WriteHeader(http.StatusOK)
			err := json.NewEncoder(w).Encode(RootTokenControlResponse{
				Complete: false,
				Otp:      "jzEHVfxe6w0Q0yz5jQuvlQG557",
				Nonce:    "2dbd10f1-8528-6246-09e7-82b25b8aba63",
			})
			require.NoError(t, err)
		case 3:
			assert.Equal(t, "PUT", theMethod)
			assert.Equal(t, RootTokenRetrievalAPI, thePath)
			w.WriteHeader(http.StatusOK)
			err := json.NewEncoder(w).Encode(RootTokenRetrievalResponse{
				Complete:     true,
				EncodedToken: "GVQfeQ5eIQ5+IlczQy0JBw80ITI6FHFme3w",
			})
			require.NoError(t, err)
		}
	}))
	defer ts.Close()

	client := createClient(t, ts.URL, mockLogger)

	// Act
	var rootToken string
	rootToken, err := client.RegenRootToken([]string{"dGVzdC1rZXktMQ==", "dGVzdC1rZXktMgo="})

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "s.Z1X8YkHUgbsTs2eeTDVE6SNK", rootToken)
}
