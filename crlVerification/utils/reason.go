/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package utils

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"reflect"
)

type RevocationReason int

// The following is an enumeration that, for a given revocation, the CA is claiming is the reason for said revocation.
//
//	https://tools.ietf.org/html/rfc5280#section-5.3.1
//
// Integers 0-10 (inclusive) are reserved by RFC 5280. As this field is optional, this program reserves -1
// to mean "not given" (either from the CCADB or a CA).
//
//	(0) unspecified
//	(1) keyCompromise
//	(2) cACompromise
//	(3) affiliationChanged
//	(4) superseded
//	(5) cessationOfOperation
//	(6) certificateHold
//	(8) removeFromCRL
//	(9) privilegeWithdrawn
//	(10) aACompromise
const NOT_GIVEN RevocationReason = -1
const (
	UNSPECIFIED RevocationReason = iota
	KEY_COMPROMISE
	CA_COMPROMISE
	AFFILIATION_CHANGE
	SUPERSEDED
	CESSATION_OF_OPERATION
	CERTIFICATE_HOLD
	REMOVE_FROM_CRL
	PRIVILEGE_WITHDRAWN
	AA_COMPROMISE
)

func (r RevocationReason) String() string {
	switch r {
	case NOT_GIVEN:
		return "no reason given"
	case UNSPECIFIED:
		return "(0) unspecified"
	case KEY_COMPROMISE:
		return "(1) keyCompromise"
	case CA_COMPROMISE:
		return "(2) cACompromise"
	case AFFILIATION_CHANGE:
		return "(3) affiliationChanged"
	case SUPERSEDED:
		return "(4) superseded"
	case CESSATION_OF_OPERATION:
		return "(5) cessationOfOperation"
	case CERTIFICATE_HOLD:
		return "(6) certificateHold"
	case REMOVE_FROM_CRL:
		return "(8) removeFromCRL"
	case PRIVILEGE_WITHDRAWN:
		return "(9) privilegeWithdrawn"
	case AA_COMPROMISE:
		return "(10) aACompromise"
	default:
		panic(fmt.Sprintf(`programming error: accounted for RevocationReason enum %v`, int(r)))
	}
}

func FromString(str *string) (RevocationReason, error) {
	if str == nil {
		return NOT_GIVEN, nil
	}
	switch *str {
	case "(0) unspecified":
		return UNSPECIFIED, nil
	case "(1) keyCompromise":
		return KEY_COMPROMISE, nil
	case "(2) cACompromise":
		return CA_COMPROMISE, nil
	case "(3) affiliationChanged":
		return AFFILIATION_CHANGE, nil
	case "(4) superseded":
		return SUPERSEDED, nil
	case "(5) cessationOfOperation":
		return CESSATION_OF_OPERATION, nil
	case "(6) certificateHold":
		return CERTIFICATE_HOLD, nil
	case "(8) removeFromCRL":
		return REMOVE_FROM_CRL, nil
	case "(9) privilegeWithdrawn":
		return PRIVILEGE_WITHDRAWN, nil
	case "(10) aACompromise":
		return AA_COMPROMISE, nil
	default:
		return NOT_GIVEN, errors.New(fmt.Sprintf(`unknown revocation reason "%s""`, *str))
	}
}

type RevocationReasonError struct {
	wanted RevocationReason
	got    RevocationReason
}

func (r RevocationReasonError) Error() string {
	return fmt.Sprintf("Revocation reasons did not match. We wanted %s, but got %s", r.wanted, r.got)
}

var revocationReasonOID asn1.ObjectIdentifier = []int{2, 5, 29, 21}

func ValidateRevocationReason(cert pkix.RevokedCertificate, ourReason RevocationReason) error {
	for _, ext := range cert.Extensions {
		// Iterate over the extensions, if any, and check
		// to see if the extension is a revocation reason code.
		if reflect.DeepEqual(ext.Id, revocationReasonOID) {
			// We found it, so lets comapare it.
			theirReason := asn1ToRevocationReason(ext.Value)
			if theirReason == ourReason {
				// Everything is fine - we found it and it matches.
				return nil
			}
			// Otherwise it differed.
			return RevocationReasonError{ourReason, theirReason}
		}
	}
	// The CRL did not provide a reason.
	if ourReason == NOT_GIVEN {
		// So if we didn't ask for one, then everything is ok.
		return nil
	}
	// Else, error.
	return RevocationReasonError{ourReason, NOT_GIVEN}
}

func asn1ToRevocationReason(data []byte) RevocationReason {
	// An ASN1 Enumerated has a minimum of three bytes.
	//
	//	0. The number 10, signifying that it is an enum.
	//	1. The number of bytes that follow (n).
	//	2-n. The enumeration value.
	//
	// A revocation reason code has only ten values
	// so we only  need the second index.
	return RevocationReason(int(data[2]))
}
