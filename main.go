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

const (
	configDirectory = "./res"
	configDirEnv    = "EDGEX_CONF_DIR"
)

var Configuration types.Config

func main() {
	start := time.Now()

	Configuration, err := initializeConfig()
	security.LoggingClient = logger.NewClient(types.CoreSecurityServiceKey, false, Configuration.LogTarget, Configuration.LogLevel)
	if err != nil {
		security.LoggingClient.Error(err.Error())
	}

	security.LoggingClient.Info("Service dependencies resolved...")
	security.LoggingClient.Info(fmt.Sprintf("Starting %s %s", types.CoreSecurityServiceKey, getSecurityVersion()))

	http.TimeoutHandler(nil, time.Millisecond*time.Duration(Configuration.Service.Timeout), "Request timed out")
	security.LoggingClient.Info(Configuration.Service.StartupMsg)

	security.SecurityClient, err = security2.NewSecurityClient(Configuration)
	if err != nil {
		security.LoggingClient.Error(err.Error())
		security.LoggingClient.Warn(fmt.Sprintf("terminating"))
		os.Exit(1)
	}

	errs := make(chan error, 2)
	listenForInterrupt(errs)
	startHttpServer(errs, Configuration.Service.Port)

	// Time it took to start service
	security.LoggingClient.Info("Service started in: " + time.Since(start).String())
	security.LoggingClient.Info("Listening on port: " + strconv.Itoa(Configuration.Service.Port))
	c := <-errs
	security.LoggingClient.Warn(fmt.Sprintf("terminating: %v", c))

	os.Exit(0)
}

func initializeConfig() (types.Config, error) {
	path := os.Getenv(configDirEnv)

	if len(path) == 0 { //Var is not set
		path = configDirectory
	}
	fileName := path + "/" + types.ConfigFileName
	contents, err := ioutil.ReadFile(fileName)
	if err != nil {
		msg := fmt.Sprintf("could not load configuration file (%s): %s", fileName, err.Error())
		return types.Config{}, errors.New(msg)
	}

	// Decode the configuration from TOML
	err = toml.Unmarshal(contents, &Configuration)
	if err != nil {
		msg := fmt.Sprintf("unable to parse configuration file (%s): %s", fileName, err.Error())
		return types.Config{}, errors.New(msg)
	}

	return Configuration, nil
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

	if strings.HasSuffix(s, "\n") {
		return s[:len(s)-len("\\")]
	}
	return s
}
