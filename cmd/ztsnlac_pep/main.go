package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PEP/internal/app/config"
	confInit "github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PEP/internal/app/init"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PEP/internal/app/logger"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PEP/internal/app/scenario"
)

var (
	confFilePath      string
	dataFile          string
	logFilePath       string
	sysLogger         *logrus.Logger
	maxConcurrentJobs int
)

func init() {
	var err error

	// Operating input parameters
	flag.StringVar(&confFilePath, "c", "./config/config.yml", "Path to user defined YML config file")
	flag.StringVar(&dataFile, "d", "./scenarios/data.json", "Path to the scenarios in JSON format")
	flag.StringVar(&logFilePath, "log", "", "path to the log file (if set, overrides the config file value)")
	flag.IntVar(&maxConcurrentJobs, "n", 1, "Number of concurrent requests")
	flag.Parse()

	// Loading all config parameter from config file defined in "confFilePath"
	err = config.LoadConfig(confFilePath)
	if err != nil {
		log.Fatal(err)
	}

	// init system logger
	confInit.InitSysLoggerParams()

	// If log file path has been given through the program arguments, update the value in the config
	if logFilePath != "" {
		config.Config.SysLogger.LogDestination = logFilePath
	}

	// Create an instance of the system logger
	sysLogger = logrus.New()

	logger.SetLoggerDestination(sysLogger)
	logger.SetLoggerLevel(sysLogger)
	logger.SetLoggerFormatter(sysLogger)
	logger.SetupCloseHandler(sysLogger)

	sysLogger.Debugf("loading logger configuration from '%s' - OK", confFilePath)

	// Create Certificate Pools for the CA certificates used by the Policy Information Point
	config.Config.CACertPoolToVerifyClientRequests = x509.NewCertPool()

	if err = confInit.InitConfig(sysLogger); err != nil {
		sysLogger.Fatalf("main: init(): %s", err.Error())
	}
}

func main() {

	scenarios, err := scenario.LoadScenariosFromFile(dataFile)
	if err != nil {
		sysLogger.Fatalf("main: main(): unable to load scenarios from '%s': %s", dataFile, err.Error())
	}
	sysLogger.Debugf("%d scenario(s) are loaded successfully", len(scenarios))

	tr, err := prepareHttpTransport()
	if err != nil {
		log.Fatal(err)
	}

	// Create an HTTPS client
	client := &http.Client{Transport: tr}

	var wg sync.WaitGroup

	for i := 0; i < maxConcurrentJobs; i++ {
		wg.Add(1)
		go func(count int) {
			_, err := runScenarios(client, scenarios, count)
			if err != nil {
				sysLogger.Errorf("error during processing of scenario")
			}
			wg.Done()
		}(i)
	}

	wg.Wait()
}

// func runScenario(tr *http.Transport, sc *scenario.Scenario) (time.Duration, error) {
func runScenarios(client *http.Client, scenarios []scenario.Scenario, jobID int) ([]time.Duration, error) {
	var d time.Duration
	var scenarioJSON []byte
	var err error

	times := make([]time.Duration, 0)

	for _, sc := range scenarios {
		scenarioJSON, err = json.Marshal(sc)
		if err != nil {
			return []time.Duration{}, err
		}
		scenarioBytes := bytes.NewBuffer(scenarioJSON)

		t := time.Now()

		resp, err := client.Post(config.Config.Pe.TargetAddr, "application/json", scenarioBytes)
		if err != nil {
			return []time.Duration{}, err
		}

		d = time.Since(t)
		times = append(times, d)

		switch resp.StatusCode {

		case http.StatusOK:
			sysLogger.WithFields(logrus.Fields{
				"scenario":                 sc.Id,
				"service":                  sc.Service,
				"action":                   sc.Action,
				"access time":              sc.AccessTime,
				"decision making duration": d,
				"authorization decision":   "GRANTED",
				"jobID":                    jobID + 1,
			}).Info("decision request")

		case http.StatusUnauthorized:
			sysLogger.WithFields(logrus.Fields{
				"scenario":                 sc.Id,
				"service":                  sc.Service,
				"action":                   sc.Action,
				"access time":              sc.AccessTime,
				"decision making duration": d,
				"authorization decision":   "DENIED",
				"jobID":                    jobID + 1,
			}).Info("decision request")

		default:
			sysLogger.Errorf("unexpected response status code: %d", resp.StatusCode)
		}
	}
	return times, nil
}

func prepareHttpTransport() (*http.Transport, error) {
	cert, err := tls.LoadX509KeyPair(config.Config.Pep.SSLCert, config.Config.Pep.SSLCertKey)
	if err != nil {
		return nil, err
	}

	// Create a CA certificate pool
	caCert, err := os.ReadFile(config.Config.Pep.CACertsToVerifyClientRequests[0])
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConns = 100
	tr.MaxConnsPerHost = 100
	tr.MaxIdleConnsPerHost = 100
	tr.TLSClientConfig = &tls.Config{
		RootCAs:      caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
	}
	return tr, nil
}
