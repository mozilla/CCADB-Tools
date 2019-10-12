/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package model

import (
	"crypto/x509"
	"encoding/json"
	"github.com/mozilla/CCADB-Tools/capi/lib/certificateUtils"
	"github.com/mozilla/CCADB-Tools/capi/lib/expiration"
	"github.com/mozilla/CCADB-Tools/capi/lib/lint/x509lint"
	"github.com/mozilla/CCADB-Tools/capi/lib/revocation/crl"
	"github.com/mozilla/CCADB-Tools/capi/lib/revocation/ocsp"
)

type TestWebsiteResult struct {
	SubjectURL  string
	RecordID    string `json:"RecordID,omitempty"`
	Expectation string
	Chain       ChainResult
	Opinion     Opinion
	Error       string
}

func NewTestWebsiteResult(subject, expectation string) TestWebsiteResult {
	return TestWebsiteResult{
		SubjectURL:  subject,
		Expectation: expectation,
		Opinion:     NewOpinion(),
	}
}

func (t TestWebsiteResult) SetRecordID(id string) TestWebsiteResult {
	t.RecordID = id
	return t
}

type ChainResult struct {
	Leaf          CertificateResult
	Intermediates []CertificateResult
	Root          CertificateResult
}

type OpinionResult = bool

const (
	PASS OpinionResult = true
	FAIL OpinionResult = false
)

type Opinion struct {
	Result OpinionResult // Whether this opinion thinks the run is bad in some way.
	Errors []Concern
}

func (o Opinion) MarshalJSON() ([]byte, error) {
	var result string
	switch o.Result {
	case PASS:
		result = "PASS"
	case FAIL:
		result = "FAIL"
	}
	return json.Marshal(struct {
		Result string
		Errors []Concern
	}{
		Result: result,
		Errors: o.Errors,
	})
}

func NewOpinion() Opinion {
	return Opinion{
		Result: FAIL,
		Errors: make([]Concern, 0),
	}
}

func (o *Opinion) Append(other Opinion) {
	o.Errors = append(o.Errors, other.Errors...)
}

type Concern struct {
	Raw            string // The raw response from, say, the OCSP or certutil tools
	Interpretation string // What this tool thinks is wrong.
	Advise         string // Any advise for troubleshooting
}

type CertificateResult struct {
	*x509.Certificate `json:"-"`
	Fingerprint       string
	CrtSh             string
	CommonName        string
	OCSP              []ocsp.OCSP
	CRL               []crl.CRL
	Expiration        expiration.ExpirationStatus
	X509Lint x509lint.X509Lint
}

func NewCeritifcateResult(certificate *x509.Certificate, ocspResonse []ocsp.OCSP, crlStatus []crl.CRL, expirationStatus expiration.ExpirationStatus, x509Lint x509lint.X509Lint) CertificateResult {
	return CertificateResult{
		certificate,
		certificateUtils.FingerprintOf(certificate),
		"https://crt.sh/?q=" + certificateUtils.FingerprintOf(certificate),
		certificate.Subject.CommonName,
		ocspResonse,
		crlStatus,
		expirationStatus,
		x509Lint,
	}
}
