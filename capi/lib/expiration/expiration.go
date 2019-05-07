/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package expiration

import (
	"crypto/x509"
	"github.com/mozilla/CCADB-Tools/capi/lib/expiration/certutil"
	"github.com/pkg/errors"
)

type Status string

const (
	Valid              Status = "valid"
	Expired                   = "expired"
	IssuerUnknown             = "issuerUnknown"
	UnexpectedResponse        = "unexpectedResponse"
)

func toStatus(nssResponse string) (Status, bool) {
	status, ok := map[string]Status{
		certutil.VALID:         Valid,
		certutil.EXPIRED:       Expired,
		certutil.ISSUER_UNKOWN: IssuerUnknown,
	}[nssResponse]
	return status, ok
}

type ExpirationStatus struct {
	Raw    string `json:"-"`
	Error  string
	Status Status
}

func VerifyChain(chain []*x509.Certificate) ([]ExpirationStatus, error) {
	statuses := make([]ExpirationStatus, len(chain))
	c, err := certutil.NewCertutil()
	if err != nil {
		return statuses, errors.Wrap(err, "failed to initialize a new NSS certificate database")
	}
	defer c.Delete()
	for _, cert := range chain {
		out, err := c.Install(cert)
		o := string(out)
		if err != nil {
			return statuses, errors.Wrapf(err, "failed to install certificate, %v", o)
		}
	}
	for i, cert := range chain {
		statuses[i] = queryExpiration(cert, c)
	}
	return statuses, nil
}

func queryExpiration(certificate *x509.Certificate, c certutil.Certutil) (exps ExpirationStatus) {
	// @TODO try to figure certutil's error codes. It uses non zero codes when the answer is
	// anything other than just "valid", so it's not a reliable way to know whether or not
	// the tool was fundamentally used wrong or if the cert is just expired or what.
	resp, _ := c.Verify(certificate)
	response := string(resp)
	exps.Raw = response
	switch status, ok := toStatus(response); ok {
	case true:
		exps.Status = status
	case false:
		exps.Error = response
		exps.Status = UnexpectedResponse
	}
	return
}
