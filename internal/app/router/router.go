// Package router contains the main routine of the PIP service.
package router

import (
	"crypto/tls"
	"log"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PEP/internal/app/config"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PEP/internal/app/logger"
)

type Router struct {
	tlsConfig *tls.Config
	frontend  *http.Server
	sysLogger *logrus.Logger
}

func New(logger *logrus.Logger) (*Router, error) {
	router := new(Router)

	// Set sysLogger to the one created in the init function
	router.sysLogger = logger

	// Configure the TLS configuration of the router
	router.tlsConfig = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    config.Config.CACertPoolToVerifyClientRequests,
		Certificates: []tls.Certificate{config.Config.PepCert},
	}

	// Frontend Handlers
	mux := http.NewServeMux()
	mux.Handle("/", router)

	w := logger.Writer()

	// Setting Up the Frontend Server
	router.frontend = &http.Server{
		Addr:         config.Config.Pep.ListenAddr,
		TLSConfig:    router.tlsConfig,
		ReadTimeout:  time.Hour * 1,
		WriteTimeout: time.Hour * 1,
		Handler:      mux,
		ErrorLog:     log.New(w, "", 0),
	}

	return router, nil
}

// ServeHTTP gets called if a request receives the PEP. The function implements
// the PEP's main routine: It performs basic authentication, authorization with
// help of the PEP, transformation from SFCs into SFPs with help of the SFP
// Logic, and then forwards the package along the SFP.
func (router *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Log all http requests incl. TLS informaion in the case of a successful TLS handshake
	logger.LogHTTPRequest(router.sysLogger, req)
}

func (router *Router) ListenAndServeTLS() error {
	return router.frontend.ListenAndServeTLS("", "")
}
