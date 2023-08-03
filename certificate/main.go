/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* The following contains some adapted code from:
* https://github.com/mozilla/tls-observatory */

package main

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"os"

	"github.com/gin-contrib/logger"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	// ReleaseMode is for production -- no debugging
	gin.SetMode(gin.ReleaseMode)

	// Default to port 8080 if PORT env var is not set
	port := getPortEnv("PORT", "8080")

	router := gin.Default()
	// Use zerolog for gin's logging
	router.Use(logger.SetLogger())
	router.POST("/certificate", postCertificate)
	err := router.Run(":" + port)
	if err != nil {
		return
	}
}

// getPortEnv looks for the PORT env var and uses fallback if not set
func getPortEnv(port, fallback string) string {
	if value, ok := os.LookupEnv(port); ok {
		return value
	}
	return fallback
}

// postCertificate does all of the certificate parsing on POST
func postCertificate(c *gin.Context) {
	logger.SetLogger()

	certHeader, err := c.FormFile("certificate")
	if err != nil {
		log.Error().Err(err).Msg("Could not read certificate from request")
		c.String(http.StatusBadRequest, "Could not read certificate from request: %s", err.Error())
		return
	}

	certReader, err := certHeader.Open()
	if err != nil {
		log.Error().Err(err).Msg("Could not open certificate from form data")
		c.String(http.StatusBadRequest, "Could not open certificate from form data: %s", err.Error())
		return
	}

	certPEM, err := io.ReadAll(certReader)
	if err != nil {
		log.Error().Err(err).Msg("Could not read certificate from form data")
		c.String(http.StatusBadRequest, "Could not read certificate from form data: %s", err.Error())
		return
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Error().Err(err).Msg("Failed to parse certificate PEM")
		c.String(http.StatusBadRequest, "Failed to parse certificate PEM")
		return
	}

	certX509, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Error().Err(err).Msg("Could not parse X.509 certificate")
		c.String(http.StatusBadRequest, "Could not parse X.509 certificate: %s", err.Error())
		return
	}

	cert := CertToJSON(certX509)

	c.JSON(http.StatusCreated, cert)
}
