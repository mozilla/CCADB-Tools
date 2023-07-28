package main

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func main() {
	router := gin.Default()
	router.POST("/certificate", postCertificate)

	router.Run("localhost:8080")
}

func postCertificate(c *gin.Context) {
	certHeader, err := c.FormFile("certificate")
	if err != nil {
		log.Error().Err(err).Msg("Could not read certificate from request")
		c.String(http.StatusBadRequest, "Could not read certificate from request: %s", err.Error())
		return
	}

	certReader, err := certHeader.Open()
	if err != nil {
		log.Error().Err(err).Msg("Could not read certificate from request")
		c.String(http.StatusBadRequest, "Could not open certificate from form data: %s", err.Error())
		return
	}

	certPEM, err := io.ReadAll(certReader)
	if err != nil {
		log.Error().Err(err).Msg("Could not read certificate from request")
		c.String(http.StatusBadRequest, "Could not read certificate from form data: %s", err.Error())
		return
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		log.Error().Err(err).Msg("Could not read certificate from request")
		c.String(http.StatusBadRequest, "Failed to parse certificate PEM", err.Error())
		return
	}

	certX509, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Error().Err(err).Msg("Could not read certificate from request")
		c.String(http.StatusBadRequest, "Could not parse X.509 certificate: %s", err.Error())
		return
	}

	certHash := SHA256Hash(certX509.Raw)
	var valInfo ValidationInfo
	cert := CertToStored(certX509, certHash, "", "", "", &valInfo)

	log.Print(cert)

	c.IndentedJSON(http.StatusCreated, cert)
}
