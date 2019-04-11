package security

import (
	"encoding/json"
	"net/http"

	"github.com/edgexfoundry-holding/go-mod-core-security/pkg/interfaces"
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

	// Configuration
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

		encode(value, w)
		return
	case http.MethodPost:
		err := SecurityClient.SetValue(key)
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
