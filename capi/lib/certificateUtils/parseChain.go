/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package certificateUtils

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	BeginCertificate = `-----BEGIN CERTIFICATE-----`
	EndCertificate   = `-----END CERTIFICATE-----`
)

func ParseChain(provided []byte) (chain []*x509.Certificate, err error) {
	var cert *x509.Certificate
	provided = bytes.TrimSpace(provided)
	for _, c := range bytes.SplitAfter(provided, []byte(EndCertificate)) {
		if len(c) == 0 {
			continue
		}
		var fmtedPEM []byte
		fmtedPEM, err = NormalizePEM(c)
		if err != nil {
			return
		}
		block, _ := pem.Decode(fmtedPEM)
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.WithFields(log.Fields{
				"fullchain":    string(provided),
				"failedMember": string(fmtedPEM),
			})
			log.WithError(err)
			log.WithTime(time.Now())
			log.Error("An individual member of a chain provided to ParseChain failed to be parsed by x509.ParseCertificate")
			return
		}
		chain = append(chain, cert)
	}
	return
}

func GatherCertificateChain(subjectURL string) ([]*x509.Certificate, error) {
	log.WithField("SubjectURL", subjectURL).Info("Gathering certificates")
	// This is very mandatory otherwise the HTTP package will vomit on revoked/expired certificates and return an error.
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: transport}
	// You have ten seconds to comply.
	client.Timeout = time.Duration(10 * time.Second)
	req, err := http.NewRequest("GET", subjectURL, nil)
	if err != nil {
		return []*x509.Certificate{}, err
	}
	req.Header.Add("X-Automated-Tool", "https://github.com/mozilla/CCADB-Tools/capi CCADB test website verification tool")
	resp, err := client.Do(req)
	if err != nil {
		return []*x509.Certificate{}, err
	}
	if err := resp.Body.Close(); err != nil {
		log.WithField("URL", subjectURL)
		log.WithError(err)
		log.WithTime(time.Now())
		log.Warnln("The body of the HTTP response failed to close when retrieving a subject's certificate " +
			"chain. This is generally fine as we do not use any content within the body, however a failure from the " +
			"remote server to response may be concerning.")
	}
	return resp.TLS.PeerCertificates, err
}

func EmplaceRoot(chain []*x509.Certificate, root *x509.Certificate) []*x509.Certificate {
	switch IncludesTrustAnchor(chain) {
	case true:
		chain[len(chain)-1] = root
		return chain
	default:
		return append(chain, root)
	}
}

func IncludesTrustAnchor(chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}
	anchor := chain[len(chain)-1]
	return bytes.Equal(anchor.RawSubject, anchor.RawIssuer)
}

func BrokenEdges(chain []*x509.Certificate) [][2]Fingerprint {
	brokenEdges := make([][2]Fingerprint, 0)
	for i, cert := range chain[:len(chain)-1] {
		issuer := chain[i+1]
		if !bytes.Equal(cert.RawIssuer, issuer.RawSubject) {
			brokenEdges = append(brokenEdges, [2]Fingerprint{FingerprintOf(cert), FingerprintOf(issuer)})
		}
	}
	return brokenEdges
}

var pemStripper = regexp.MustCompile(
	`(` +
		strings.Join([]string{`\n`, `'`, BeginCertificate, EndCertificate}, `|`) +
		`)`)

// NormalizePEM ignores any formatting or string artifacts that the PEM may have had
// and applies https://tools.ietf.org/html/rfc1421
func NormalizePEM(pem []byte) (fmtedPEM []byte, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = e.(error)
		}
	}()
	pem = pemStripper.ReplaceAll(pem, []byte{})
	fmtedPEM = append(fmtedPEM, BeginCertificate+"\n"...)
	width := 64 // Columns per line https://tools.ietf.org/html/rfc1421
	for len(pem) > 0 {
		if len(pem) < width {
			width = len(pem)
		}
		fmtedPEM = append(fmtedPEM, pem[:width]...)
		fmtedPEM = append(fmtedPEM, '\n')
		pem = pem[width:]
	}
	fmtedPEM = append(fmtedPEM, EndCertificate...)
	return
}

type Fingerprint = string

func FingerprintOf(cert *x509.Certificate) Fingerprint {
	hasher := crypto.SHA256.New()
	hasher.Write(cert.Raw)
	return fmt.Sprintf("%X", hasher.Sum(nil))
}
