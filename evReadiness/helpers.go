/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/rs/xid"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type Chain struct {
	Domain string
	IP     string
	// base64 DER encoded certificates
	Certs []string
}

type NoTLSCertsErr string

func (f NoTLSCertsErr) Error() string {
	return fmt.Sprintf("No TLS Certs Received")
}

// checkEvReadyExecExists checks if the executable is present -- if it's not, exit,
// because it's the brains behind everything
func checkEvReadyExecExists(path string) {
	path, err := exec.LookPath(path)
	if err != nil {
		slog.Error("ev-ready executable not found... exiting.")
		os.Exit(127)
	}
}

// hostnameValidator validates and cleans up the entered hostname
func hostnameValidator(hostname string) string {
	u, err := url.Parse(strings.TrimSpace(hostname))
	if err != nil {
		slog.Error("Unable to parse hostname url.", "Error", err.Error())
	}
	if u.IsAbs() {
		return u.Hostname()
	} else {
		return strings.TrimSuffix(u.Path, "/")
	}
}

// oidValidator validates and cleans up the entered OID
func oidValidator(oid string) bool {
	re := regexp.MustCompile(`^([0-2])((\.0)|(\.[1-9][0-9]*))*$`)

	return re.MatchString(strings.TrimSpace(oid))
}

// pemValidator validates and cleans up the pasted PEM content
func pemValidator(pem string) bool {
	pem = strings.TrimSpace(pem)
	return strings.HasPrefix(pem, "-----BEGIN CERTIFICATE-----") &&
		strings.HasSuffix(pem, "-----END CERTIFICATE-----")
}

// handleCert retrieves certificates from a host, builds a chain file in PEM format
// and returns the filename of the newly created PEM file
func handleCert(domain, certUpload string) (string, error) {
	// Generate a guid to prevent filename conflicts in the case of simulataneous uploads or PEM checks
	guid := xid.New()
	filePath := "/tmp/" + guid.String()

	certs, ip, err := retrieveCertFromHost(domain, "443", true)

	if err != nil {
		slog.Error("Could not retrieve certs.", "domain", domain, "error", err.Error())
	}

	if certs == nil {
		e := new(NoTLSCertsErr)
		slog.Error("Could not retrieve certs.", "error", e.Error())
	}

	var chain = Chain{}

	chain.Domain = domain

	chain.IP = ip

	f, err := os.Create(filePath + ".pem")
	if err != nil {
		slog.Error("Unable to create certs file.", "Error", err.Error())
	}
	defer f.Close()

	for _, cert := range certs {
		_, err := f.WriteString(createPEM(cert.Raw))
		if err != nil {
			slog.Error("Unable to write certs to file.", "Error", err.Error())
		}
		chain.Certs = append(chain.Certs, base64.StdEncoding.EncodeToString(cert.Raw))

	}
	_, err = f.WriteString(certUpload)
	if err != nil {
		slog.Error("Unable to write uploaded cert to PEM chain file.",
			"Error", err.Error())
	}

	return f.Name(), f.Sync()
}

// retrieveCertFromHost checks the host connectivity and returns the certificate chain (if any) provided
// by the domain or an error in every other case.
func retrieveCertFromHost(domainName, port string, skipVerify bool) ([]*x509.Certificate, string, error) {
	config := tls.Config{InsecureSkipVerify: skipVerify}
	canonicalName := domainName + ":" + port
	ip := ""
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", canonicalName, &config)
	if err != nil {
		return nil, ip, err
	}
	defer conn.Close()

	ip = strings.TrimSuffix(conn.RemoteAddr().String(), ":443")

	certs := conn.ConnectionState().PeerCertificates
	if certs == nil {
		return nil, ip, errors.New("could not get server's certificate from the TLS connection")
	}

	return certs, ip, nil
}

// createPEM takes raw bytes and returns a properly formatted PEM string
func createPEM(rawCert []byte) string {
	certString := base64.StdEncoding.EncodeToString(rawCert)
	lineLength := 64
	runes := []rune(certString)
	prefix := "-----BEGIN CERTIFICATE-----"
	suffix := "-----END CERTIFICATE-----\n"

	pem := make([]string, 0)
	pem = append(pem, prefix)

	for i := 0; i < len(runes); i += lineLength {
		if i+lineLength < len(runes) {
			pem = append(pem, string(runes[i:(i+lineLength)]))
		} else {
			pem = append(pem, string(runes[i:]))
		}
	}
	pem = append(pem, suffix)

	return strings.Join(pem, "\n")
}
