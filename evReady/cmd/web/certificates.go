package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"github.com/rs/xid"
	"net"
	"os"
	"strings"
	"time"
)

type CertChain struct {
	Hostname string
	IP       string
	Certs    []string
}

func getCertFromHost(hostname, port string, skipVerify bool) ([]*x509.Certificate, string, error) {
	config := tls.Config{InsecureSkipVerify: skipVerify}
	canonicalName := hostname + ":" + port
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

func certConvert(rawCert []byte) string {
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

func (app *application) pemCreator(hostname, rootCert string) (string, error) {
	certs, ip, err := getCertFromHost(hostname, "443", true)
	if err != nil || certs == nil {
		app.logger.Error("Unable to retrieve cert from host.", "hostname", hostname, "error", err.Error())
	}

	certChain := CertChain{
		Hostname: hostname,
		IP:       ip,
	}

	f, err := os.Create("/tmp/" + xid.New().String() + ".pem")
	if err != nil {
		app.logger.Error("Unable to create certs file.", "error", err.Error())
	}
	defer f.Close()

	for _, cert := range certs {
		_, err := f.WriteString(certConvert(cert.Raw))
		if err != nil {
			app.logger.Error("Unable to write certs to file.", "error", err.Error())
		}
		certChain.Certs = append(certChain.Certs, base64.StdEncoding.EncodeToString(cert.Raw))

	}
	_, err = f.WriteString(rootCert)
	if err != nil {
		app.logger.Error("Unable to write cert to PEM chain file.", "error", err.Error())
	}

	return f.Name(), f.Sync()
}

func (app *application) certCleanup(pemFile string) {
	err := os.RemoveAll(pemFile)
	if err != nil {
		app.logger.Error("Unable to delete PEM files or directories", "Error", err.Error())
	} else {
		app.logger.Info("Removed unused PEM file", "File", pemFile)
	}
}
