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

	router := gin.Default()
	router.Use(logger.SetLogger())
	router.POST("api/v1/certificate", postCertificate)
	router.Run(":443")
}

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

	block, _ := pem.Decode([]byte(certPEM))
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

	certHash := SHA256Hash(certX509.Raw)
	var valInfo ValidationInfo
	cert := CertToStored(certX509, certHash, "", "", "", &valInfo)

	c.JSON(http.StatusCreated, cert)
}
