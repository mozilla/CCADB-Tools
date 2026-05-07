/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package expiration

import (
	"bytes"
	"crypto/x509"
	"time"
)

type Status string

const (
	Valid              Status = "valid"
	Expired            Status = "expired"
	IssuerUnknown      Status = "issuerUnknown"
	UnexpectedResponse Status = "unexpectedResponse"
)

type ExpirationStatus struct {
	Raw    string `json:"-"`
	Error  string
	Status Status
}

func VerifyChain(chain []*x509.Certificate) ([]ExpirationStatus, error) {
	return verifyChainAt(chain, time.Now()), nil
}

func verifyChainAt(chain []*x509.Certificate, now time.Time) []ExpirationStatus {
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	for _, cert := range chain {
		if isSelfIssued(cert) {
			roots.AddCert(cert)
		} else {
			intermediates.AddCert(cert)
		}
	}
	statuses := make([]ExpirationStatus, len(chain))
	for i, cert := range chain {
		statuses[i] = queryExpiration(cert, roots, intermediates, now)
	}
	return statuses
}

func queryExpiration(cert *x509.Certificate, roots, intermediates *x509.CertPool, now time.Time) ExpirationStatus {
	if now.After(cert.NotAfter) {
		return ExpirationStatus{Status: Expired}
	}
	if isSelfIssued(cert) {
		// Verify the self-signature, but tolerate algorithms Go marks as
		// insecure (e.g. SHA1WithRSA) so legacy roots aren't reported as
		// IssuerUnknown.
		err := cert.CheckSignatureFrom(cert)
		if _, ok := err.(x509.InsecureAlgorithmError); err == nil || ok {
			return ExpirationStatus{Status: Valid}
		}
		return ExpirationStatus{Raw: err.Error(), Status: IssuerUnknown}
	}
	// Pin verification time inside the cert's own validity window so an
	// expired ancestor surfaces as IssuerUnknown rather than an expiration
	// error attributed to the cert under test.
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   cert.NotBefore.Add(time.Second),
	}
	if _, err := cert.Verify(opts); err != nil {
		return ExpirationStatus{Raw: err.Error(), Status: IssuerUnknown}
	}
	return ExpirationStatus{Status: Valid}
}

func isSelfIssued(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer)
}
