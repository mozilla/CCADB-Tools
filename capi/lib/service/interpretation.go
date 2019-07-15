/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package service

import (
	"fmt"
	"github.com/mozilla/CCADB-Tools/capi/lib/expiration"
	"github.com/mozilla/CCADB-Tools/capi/lib/model"
	"github.com/mozilla/CCADB-Tools/capi/lib/revocation/crl"
	"github.com/mozilla/CCADB-Tools/capi/lib/revocation/ocsp"
)

type Expectation int

const (
	None Expectation = iota
	Valid
	Expired
	Revoked
)

func (e Expectation) String() string {
	switch e {
	case None:
		return "none"
	case Valid:
		return "valid"
	case Expired:
		return "expired"
	case Revoked:
		return "revoked"
	}
	return ""
}

func InterpretResult(result *model.TestWebsiteResult, expectation Expectation) {
	switch expectation {
	case Valid:
		//////// Expiration checks
		// Leaf must NOT be expired
		result.Opinion.Append(assertNotExpired(result.Chain.Leaf, Leaf))
		// Intermediates must NOT be expired
		for _, intermediate := range result.Chain.Intermediates {
			result.Opinion.Append(assertNotExpired(intermediate, Intermediate))
		}
		// Root must NOT be expired.
		result.Opinion.Append(assertNotExpired(result.Chain.Root, Root))
		/////// Revocation checks
		// Leaf MUST be Good
		result.Opinion.Append(assertNotRevoked(result.Chain.Leaf, Leaf))
		// Intermediates MUST be Good.
		for _, intermediate := range result.Chain.Intermediates {
			result.Opinion.Append(assertNotRevoked(intermediate, Intermediate))
		}
		// Root must be Good
		result.Opinion.Append(assertNotRevoked(result.Chain.Root, Root))
	case Expired:
		//////// Expiration checks
		// Leaf MUST be expired
		result.Opinion.Append(assertExpired(result.Chain.Leaf, Leaf))
		// Intermediates MAY be expired
		for _, intermediate := range result.Chain.Intermediates {
			result.Opinion.Append(assertMayBeExpired(intermediate, Intermediate))
		}
		// Root must NOT be expired.
		result.Opinion.Append(assertNotExpired(result.Chain.Root, Root))
		/////// Revocation checks
		//
		// By policy, we do not care whether or not the leaf certificate
		// is revoked by any CRL or OCSP responder.
		//
		// Intermediates may be good (or Unauthorized iff they are expired)
		for _, intermediate := range result.Chain.Intermediates {
			result.Opinion.Append(assertNotRevoked(intermediate, Intermediate))
		}
		// Root must be Good
		result.Opinion.Append(assertNotRevoked(result.Chain.Root, Root))
	case Revoked:
		//////// Expiration checks
		// Leaf must not be expired.
		result.Opinion.Append(assertNotExpired(result.Chain.Leaf, Leaf))
		// Intermediates must not be expired
		for _, intermediate := range result.Chain.Intermediates {
			result.Opinion.Append(assertNotExpired(intermediate, Intermediate))
		}
		// Root must not be expired
		result.Opinion.Append(assertNotExpired(result.Chain.Root, Root))
		/////// Revocation checks
		// Leaf MUST be revoked.
		result.Opinion.Append(assertRevoked(result.Chain.Leaf, Leaf))
		// Intermediates MAY be revoked
		for _, intermediate := range result.Chain.Intermediates {
			result.Opinion.Append(assertMayBeRevoked(intermediate, Intermediate))
}
		// Root must NOT be revoked
		result.Opinion.Append(assertNotRevoked(result.Chain.Root, Root))
	}

	switch len(result.Opinion.Errors) == 0 {
	case true:
		result.Opinion.Result = model.PASS
	case false:
		result.Opinion.Result = model.FAIL
	}
}

type CertType string

const (
	Root         CertType = "root"
	Intermediate          = "intermediate"
	Leaf                  = "leaf"
)

func assertNotRevoked(cert model.CertificateResult, t CertType) (opinion model.Opinion) {
	for _, response := range cert.OCSP {
		if cert.Expiration.Status == expiration.Expired && response.Status == ocsp.Unauthorized && t != Root {
			continue
		}
		if response.Error != "" {
			interpretation := ""
			switch response.Status {
			case ocsp.CryptoVerifcationError:
				interpretation = fmt.Sprintf("OCSP responder %s could not verify the provided chain at the %s. This is usually accompanied by a verification error thrown by certutil.", response.Responder, t)
			case ocsp.BadResponse:
				interpretation = fmt.Sprintf("OCSP responder %s gave a bad response for the %s.", response.Responder, t)
			}
			opinion.Errors = append(opinion.Errors, model.Concern{
				Raw:            response.Error,
				Interpretation: interpretation,
				Advise:         cert.CrtSh,
			})
		} else if response.Status != ocsp.Good {
			opinion.Errors = append(opinion.Errors, model.Concern{
				Raw:            response.Error,
				Interpretation: fmt.Sprintf("%s is `%s` by OCSP responder %s", t, response.Status.String(), response.Responder),
				Advise:         cert.CrtSh,
			})
		}

	}
	for _, crlStatus := range cert.CRL {
		if crlStatus.Status == crl.Unchecked {
			continue
		}
		if crlStatus.Status == crl.Revoked {
			opinion.Errors = append(opinion.Errors, model.Concern{
				Raw:            "",
				Interpretation: fmt.Sprintf("%s is revoked by CRL endpoint %s", t, crlStatus.Endpoint),
				Advise:         cert.CrtSh,
			})
		}
		if crlStatus.Error != "" {
			opinion.Errors = append(opinion.Errors, model.Concern{
				Raw:            crlStatus.Error,
				Interpretation: "An error occurred while retrieving the CRL. This is usually a networking error",
				Advise:         fmt.Sprintf("If this is a networking error, attempt to verify that CRL endpoint at %s is active and available", crlStatus.Endpoint),
			})
		}
	}
	return
}

func assertNotExpired(cert model.CertificateResult, t CertType) (opinion model.Opinion) {
	if cert.Expiration.Status == expiration.Expired {
		opinion.Errors = append(opinion.Errors, model.Concern{
			Raw:            cert.Expiration.Error,
			Interpretation: fmt.Sprintf("%s is expired", t),
			Advise:         cert.CrtSh,
		})
	}
	if cert.Expiration.Status == expiration.IssuerUnknown {
		opinion.Errors = append(opinion.Errors, model.Concern{
			Raw:            cert.Expiration.Raw,
			Interpretation: fmt.Sprintf("bad chain at %s", t),
			Advise:         cert.CrtSh,
		})
	}
	if cert.Expiration.Error != "" {
		opinion.Errors = append(opinion.Errors, model.Concern{
			Raw:            cert.Expiration.Error,
			Interpretation: fmt.Sprintf("fatal error at %s", t),
			Advise:         cert.CrtSh,
		})
	}
	return
}

func assertExpired(cert model.CertificateResult, t CertType) (opinion model.Opinion) {
	if cert.Expiration.Status != expiration.Expired {
		opinion.Errors = append(opinion.Errors, model.Concern{
			Raw:            cert.Expiration.Error,
			Interpretation: fmt.Sprintf("%s is not expired", t),
			Advise:         cert.CrtSh,
		})
	}
	if cert.Expiration.Status == expiration.IssuerUnknown {
		opinion.Errors = append(opinion.Errors, model.Concern{
			Raw:            cert.Expiration.Raw,
			Interpretation: fmt.Sprintf("bad chain at %s", t),
			Advise:         cert.CrtSh,
		})
	}
	if cert.Expiration.Error != "" {
		opinion.Errors = append(opinion.Errors, model.Concern{
			Raw: cert.Expiration.Error,
			Interpretation: fmt.Sprintf("certutil encountered a fatal error when attempting to verify the %s certificate, %s",
				t, cert.Fingerprint),
			Advise: "This is likely an error in CAPI",
		})
	}
	return
}

func assertMayBeExpired(cert model.CertificateResult, t CertType) (opinion model.Opinion) {
	if cert.Expiration.Status == expiration.IssuerUnknown {
		opinion.Errors = append(opinion.Errors, model.Concern{
			Raw:            cert.Expiration.Raw,
			Interpretation: fmt.Sprintf("bad chain at %s", t),
			Advise:         cert.CrtSh,
		})
	}
	if cert.Expiration.Error != "" {
		opinion.Errors = append(opinion.Errors, model.Concern{
			Raw: cert.Expiration.Error,
			Interpretation: fmt.Sprintf("certutil encountered a fatal error when attempting to verify the %s certificate, %s",
				t, cert.Fingerprint),
			Advise: "This is likely an error in CAPI",
		})
	}
	return
}

func assertRevoked(cert model.CertificateResult, t CertType) (opinion model.Opinion) {
	for _, response := range cert.OCSP {
		if cert.Expiration.Status == expiration.Expired && response.Status == ocsp.Unauthorized && t != Root {
			continue
		}
		if response.Status == ocsp.Revoked {
			continue
		}
		if response.Error != "" {
			interpretation := ""
			switch response.Status {
			case ocsp.CryptoVerifcationError:
				interpretation = fmt.Sprintf("OCSP responder %s could not verify the provided chain at the %s. This is usually accompanied by a verification error thrown by certutil.", response.Responder, t)
			case ocsp.BadResponse:
				interpretation = fmt.Sprintf("OCSP responder %s gave a bad response for the %s.", response.Responder, t)
			}
			opinion.Errors = append(opinion.Errors, model.Concern{
				Raw:            response.Error,
				Interpretation: interpretation,
				Advise:         cert.CrtSh,
			})
		} else {
			opinion.Errors = append(opinion.Errors, model.Concern{
				Raw:            response.Status.String(),
				Interpretation: fmt.Sprintf("%s is `%s` by OCSP responder %s", t, response.Status.String(), response.Responder),
				Advise:         cert.CrtSh,
			})
		}

	}
	for _, crlStatus := range cert.CRL {
		if crlStatus.Status == crl.Unchecked {
			continue
		}
		if crlStatus.Status != crl.Revoked {
			opinion.Errors = append(opinion.Errors, model.Concern{
				Raw:            crlStatus.Error,
				Interpretation: fmt.Sprintf("%s is not revoked by CRL endpoint %s", t, crlStatus.Endpoint),
				Advise:         cert.CrtSh,
			})
		}
		if crlStatus.Error != "" {
			opinion.Errors = append(opinion.Errors, model.Concern{
				Raw:            crlStatus.Error,
				Interpretation: "An error occurred while retrieving the CRL. This is usually a networking error",
				Advise:         fmt.Sprintf("If this is a networking error, attempt to verify that CRL endpoint at %s is active and available", crlStatus.Endpoint),
			})
		}
	}
	return
}

func assertMayBeRevoked(cert model.CertificateResult, t CertType) (opinion model.Opinion) {
	for _, response := range cert.OCSP {
		if response.Status == ocsp.Revoked {
			continue
		}
		if response.Error != "" {
			interpretation := ""
			switch response.Status {
			case ocsp.CryptoVerifcationError:
				interpretation = fmt.Sprintf("OCSP responder %s could not verify the provided chain at the %s. This is usually accompanied by a verification error thrown by certutil.", response.Responder, t)
			case ocsp.BadResponse:
				interpretation = fmt.Sprintf("OCSP responder %s gave a bad response for the %s.", response.Responder, t)
			}
			opinion.Errors = append(opinion.Errors, model.Concern{
				Raw:            response.Error,
				Interpretation: interpretation,
				Advise:         cert.CrtSh,
			})
		}
	}
	for _, crlStatus := range cert.CRL {
		if crlStatus.Error != "" {
			opinion.Errors = append(opinion.Errors, model.Concern{
				Raw:            crlStatus.Error,
				Interpretation: "An error occurred while retrieving the CRL. This is usually a networking error",
				Advise:         fmt.Sprintf("If this is a networking error, attempt to verify that CRL endpoint at %s is active and available", crlStatus.Endpoint),
			})
		}
	}
	return
}
