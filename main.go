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

package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/edgexfoundry-holding/go-mod-core-security/pkg/types"
	security2 "github.com/edgexfoundry-holding/go-mod-core-security/security"
	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
	"github.com/gorilla/context"

	"github.com/edgexfoundry-holding/go-mod-core-security/internal/pkg/security"
)

func main() {
	start := time.Now()

	config, err := initializeConfig()
	security.LoggingClient = logger.NewClient(types.CoreSecurityServiceKey, false, config.LogTarget, config.LogLevel)
	if err != nil {
		security.LoggingClient.Error(err.Error())
	}

	security.LoggingClient.Info("Service dependencies resolved...")
	security.LoggingClient.Info(fmt.Sprintf("Starting %s %s", types.CoreSecurityServiceKey, getSecurityVersion()))

	http.TimeoutHandler(nil, time.Millisecond*time.Duration(config.Service.Timeout), "Request timed out")
	security.LoggingClient.Info(config.Service.StartupMsg)

	security.SecurityClient, err = security2.NewSecurityClient(config)
	if err != nil {
		security.LoggingClient.Error(err.Error())
		security.LoggingClient.Warn(fmt.Sprintf("terminating"))
		os.Exit(1)
	}

	errs := make(chan error, 2)
	listenForInterrupt(errs)
	startHttpServer(errs, config.Service.Port)

	// Time it took to start service
	security.LoggingClient.Info("Service started in: " + time.Since(start).String())
	security.LoggingClient.Info("Listening on port: " + strconv.Itoa(config.Service.Port))
	c := <-errs
	security.LoggingClient.Warn(fmt.Sprintf("terminating: %v", c))

	os.Exit(0)
}

func initializeConfig() (types.Config, error) {
	path := os.Getenv(types.ConfigDirEnv)

	if len(path) == 0 { //Var is not set
		path = types.ConfigDirectory
	}
	fileName := path + "/" + types.ConfigFileName
	contents, err := ioutil.ReadFile(fileName)
	if err != nil {
		msg := fmt.Sprintf("could not load configuration file (%s): %s", fileName, err.Error())
		return types.Config{}, errors.New(msg)
	}

	var config types.Config
	// Decode the configuration from TOML
	err = toml.Unmarshal(contents, &config)
	if err != nil {
		msg := fmt.Sprintf("unable to parse configuration file (%s): %s", fileName, err.Error())
		return types.Config{}, errors.New(msg)
	}

	return config, nil
}

func listenForInterrupt(errChan chan error) {
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, os.Interrupt)
		errChan <- fmt.Errorf("%s", <-c)
	}()
}

func startHttpServer(errChan chan error, port int) {
	go func() {
		r := security.LoadRestRoutes()
		errChan <- http.ListenAndServe(":"+strconv.Itoa(port), context.ClearHandler(r))
	}()
}

func getSecurityVersion() string {
	version, _ := ioutil.ReadFile("VERSION")
	s := string(version)
	n := "\n"

	if strings.HasSuffix(s, n) {
		return s[:len(s)-len(n)]
	}
	return s
}
