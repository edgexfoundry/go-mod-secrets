// Copyright (c) 2022 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package runtimetokenprovider

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/edgexfoundry/go-mod-secrets/v4/pkg"
	"github.com/stretchr/testify/require"
)

type testServer struct {
	serverOptions serverOptions
	server        *httptest.Server
}

type serverOptions struct {
}

func newTestServer(respOpts serverOptions) *testServer {
	return &testServer{
		serverOptions: respOpts,
	}
}

func (ts *testServer) close() {
	if ts.server != nil {
		ts.server.Close()
	}
}

func (ts *testServer) setupTestServer(t *testing.T) {
	// Setup Mock Server
	ts.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pathStrings := strings.Split(r.URL.EscapedPath(), "/")
		if len(pathStrings) > 1 {
			apiPath := "/" + strings.Join(pathStrings[1:], "/")
			switch apiPath {
			case pkg.SpiffeTokenProviderGetTokenAPI:
				if r.Method == http.MethodPost {
					w.WriteHeader(http.StatusOK)
					// Read request body
					body := make([]byte, r.ContentLength)
					if _, err := io.ReadFull(r.Body, body); err != nil {
						fmt.Println("failed read body: ", string(body), " err: ", err.Error())
						return
					}

					fmt.Println("body: ", string(body))

					_, err := w.Write([]byte("mock-token"))
					require.NoError(t, err)
				}

			default:
				w.WriteHeader(http.StatusInternalServerError)
			}
		}
	}))
}
