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

package security

import (
	"encoding/json"
	"net/http"

	"github.com/edgexfoundry-holding/go-mod-core-security/pkg/interfaces"
	"github.com/edgexfoundry-holding/go-mod-core-security/pkg/types"
	"github.com/edgexfoundry/go-mod-core-contracts/clients"
	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
	"github.com/gorilla/mux"
)

var SecurityClient interfaces.Client
var LoggingClient logger.LoggingClient

func LoadRestRoutes() *mux.Router {
	r := mux.NewRouter()

	// Ping Resource
	r.HandleFunc(clients.ApiPingRoute, pingHandler).Methods(http.MethodGet)

	// Security Resource
	r.HandleFunc(clients.ApiBase+"/security/{key}", securityHandler).Methods(http.MethodGet, http.MethodPost, http.MethodDelete)

	return r
}

// Test if the service is working
func pingHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("pong"))
}

func securityHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	// URL parameters
	key := mux.Vars(r)["key"]

	switch r.Method {
	case http.MethodGet:
		value, err := SecurityClient.GetValue(key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			LoggingClient.Error(err.Error())
			return
		}

		w.Write([]byte(value))
		return
	case http.MethodPost:
		var result map[string]interface{}
		dec := json.NewDecoder(r.Body)
		err := dec.Decode(&result)

		// Problem Decoding
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			LoggingClient.Error("Error decoding payload: " + err.Error())
			return
		}
		var payloads []types.Payload

		for k, v := range result["data"].(map[string]interface{}) {
			payloads = append(payloads, types.Payload{Key: k, Value: v.(string)})
		}

		err = SecurityClient.SetValue(payloads[0])
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			LoggingClient.Error(err.Error())
			return
		}
		break
	case http.MethodDelete:
		err := SecurityClient.DeleteValue(key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			LoggingClient.Error(err.Error())
			return
		}
		break
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("true"))
}

// Helper function for encoding things for returning from REST calls
func encode(i interface{}, w http.ResponseWriter) {
	w.Header().Add("Content-Type", "application/json")

	enc := json.NewEncoder(w)
	err := enc.Encode(i)
	// Problems encoding
	if err != nil {
		LoggingClient.Error("Error encoding the data: " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
