// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_config.yml corresponds to a function of this package.
package init

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PEP/internal/app/config"
)

// The function initializes the 'pep' section of the config file and
// loads the Policy Information Point certificate(s).
func initPep(sysLogger *logrus.Logger) error {
	var err error
	var fields string = ""

	if config.Config.Pep.SSLCert == "" {
		fields += "ssl_cert,"
	}

	if config.Config.Pep.SSLCertKey == "" {
		fields += "ssl_cert_key,"
	}

	if config.Config.Pep.CACertsToVerifyClientRequests == nil {
		fields += "ca_certs_to_verify_client_certs,"
	}

	if fields != "" {
		return fmt.Errorf("initPe(): in the section 'pep' the following required fields are missed: '%s'", strings.TrimSuffix(fields, ","))
	}

	// Read CA certs used to verify certs to be accepted
	for _, acceptedClientCert := range config.Config.Pep.CACertsToVerifyClientRequests {
		err = loadCACertificate(sysLogger, acceptedClientCert, "client", config.Config.CACertPoolToVerifyClientRequests)
		if err != nil {
			return err
		}
	}

	// Load Policy Information Point certificate
	config.Config.PepCert, err = loadX509KeyPair(sysLogger, config.Config.Pep.SSLCert, config.Config.Pep.SSLCertKey, "Policy Information Point", "")
	if err != nil {
		return err
	}

	return nil
}
