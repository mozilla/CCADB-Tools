/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* The following code is adapted from code from:
* https://github.com/mozilla/tls-observatory/blob/7bc42856d2e5594614b56c2f55baf42bb9751b3d/certificate/constraints/constraints.go
* https://github.com/jcjones/gx509/blob/master/gx509/technicalconstraints.go */

package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var oidPrecertificateSigningCertificate = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}

// IsTechnicallyConstrainedMozPolicyV29 determines if a given certificate is "considered technically constrained" according to the following requirements:
// - Mozilla Root Store Policy (MRSP) v2.9 (https://github.com/mozilla/pkipolicy/blob/2.9/rootstore/policy.md)
// - CABForum TLS Baseline Requirements (TLSBR) v2.0.1 (https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-v2.0.1.pdf)
// - CABForum S/MIME Baseline Requirements (SBR) v1.0.1 (https://cabforum.org/wp-content/uploads/CA-Browser-Forum-SMIMEBR-1.0.1.pdf)

func IsTechnicallyConstrainedMozPolicyV29(cert *x509.Certificate) bool {
	// MRSP 5.3.1: "For an intermediate certificate to be considered technically constrained, the certificate MUST include an Extended Key Usage (EKU)
	// extension specifying the extended key usage(s) allowed for the type of end entity certificates that the intermediate CA is authorized to issue."
	if len(cert.ExtKeyUsage) == 0 {
		return false
	}

	// Look for prerequisite EKUs.
	var hasServerAuth, hasEmailProtection bool
	for _, kp := range cert.ExtKeyUsage {
		switch kp {
		case x509.ExtKeyUsageAny:
			// MRSP 5.3.1: "The anyExtendedKeyUsage KeyPurposeId MUST NOT appear within this extension."
			// TLSBR 7.1.2.10.6: "anyExtendedKeyUsage   2.5.29.37.0   MUST NOT"
			// SBR 7.1.2.2(g): "anyExtendedKeyUsage SHALL NOT be present."
			return false
		case x509.ExtKeyUsageEmailProtection: // ip-kp-emailProtection
			hasEmailProtection = true
		case x509.ExtKeyUsageServerAuth: // id-kp-serverAuth
			hasServerAuth = true
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			// For certificates with a notBefore before 23 August 2016, the id-Netscape-stepUp OID (aka Netscape Server Gated Crypto ("nsSGC")) is treated as equivalent to id-kp-serverAuth.
			if cert.NotBefore.Before(time.Date(2016, time.August, 23, 0, 0, 0, 0, time.UTC)) {
				hasServerAuth = true
			}
		}
	}

	if hasServerAuth {
		// Look for disqualifying companion EKUs.

// COMMENT OUT because the following rule applies whether technically constrained or not. It does not determine if technically contrained.
//		for _, kp := range cert.ExtKeyUsage {
//			switch kp {
//			case x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageOCSPSigning:
//				// TLSBR 7.1.2.10.6: "id-kp-codeSigning   1.3.6.1.5.5.7.3.3   MUST NOT"
//				// TLSBR 7.1.2.10.6: "id-kp-emailProtection   1.3.6.1.5.5.7.3.4   MUST NOT"
//				// TLSBR 7.1.2.10.6: "id-kp-timeStamping   1.3.6.1.5.5.7.3.8   MUST NOT"
//				// TLSBR 7.1.2.10.6: "id-kp-OCSPSigning   1.3.6.1.5.5.7.3.9   MUST NOT"
//				return false
//			}
//		}
        
		for _, oid := range cert.UnknownExtKeyUsage {
			if oid.Equal(oidPrecertificateSigningCertificate) {
				// TLSBR 7.1.2.10.6: "Precertificate Signing Certificate   1.3.6.1.4.1.11129.2.4.4   MUST NOT"
				return false
			}
		}

		// MRSP 5.3.1: "If the intermediate CA certificate includes the id-kp-serverAuth extended key usage, then to be considered technically constrained,
		// the certificate MUST be name-constrained as described in section 7.1.2.5 of the TLS Baseline Requirements"
		if len(cert.PermittedDNSDomains) < 1 && !excludesAllDomains(cert) {
			// TLSBR 7.1.2.5.2: "The permittedSubtrees MUST contain at least one GeneralSubtree for...dNSName...UNLESS...excludedSubtrees...exclude[s] all names of that name type".
			return false
		} else if len(cert.PermittedIPRanges) < 1 && !excludesAllIPRanges(cert) {
			// TLSBR 7.1.2.5.2: "The permittedSubtrees MUST contain at least one GeneralSubtree for...iPAddress...UNLESS...excludedSubtrees...exclude[s] all names of that name type".
			return false
		} else {
			// TLSBR 7.1.2.5.2: "the permittedSubtrees MUST contain at least one GeneralSubtree of the directoryName GeneralName name type".
			return len(permittedDirNames(cert)) >= 1
		}
	} else if hasEmailProtection {
		// Look for disqualifying companion EKUs.
  
// COMMENT OUT because the following rule applies whether technically constrained or not. It does not determine if technically contrained.
//		for _, kp := range cert.ExtKeyUsage {
//			switch kp {
//			case x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageTimeStamping:
//				// MRSP 5.3.1: "id-kp-serverAuth...MUST NOT be present."
//				// SBR 7.1.2.2(g): "id-kp-serverAuth, id-kp-codeSigning, id-kp-timeStamping...SHALL NOT be present."
//				return false // Unconstrained
//			}
//		}

		// MRSP 5.3.1: "If the intermediate CA certificate includes the id-kp-emailProtection extended key usage, then to be considered technically constrained,
		// it MUST comply with section 7.1.5 of the S/MIME Baseline Requirements and include the Name Constraints X.509v3 extension with constraints on rfc822Name,
		// with at least one name in permittedSubtrees"
		if len(cert.PermittedEmailAddresses) < 1 {
			return false
		} else {
			// SBR 7.1.5: "SHALL include the nameConstraints X.509v3 extension with constraints on...directoryName as follows:...For each directoryName in permittedSubtrees".
			return len(permittedDirNames(cert)) >= 1
		}
	} else {
		return true // Constrained to some other EKU(s).
	}
}

func excludesAllDomains(cert *x509.Certificate) bool {
	for _, domain := range cert.ExcludedDNSDomains {
		if domain == "" {
			return true
		}
	}

	return false
}

func excludesAllIPRanges(cert *x509.Certificate) bool {
	// For iPAddresses in excludedSubtrees, both IPv4 and IPv6 must be present and the constraints must cover the entire range (0.0.0.0/0 for IPv4 and ::0/0 for IPv6).
	var excludesIPv4, excludesIPv6 bool
	for _, cidr := range cert.ExcludedIPRanges {
		if cidr.IP.Equal(net.IPv4zero) && isBufferAllZeros(cidr.Mask, net.IPv4len) {
			excludesIPv4 = true
		}
		if cidr.IP.Equal(net.IPv6zero) && isBufferAllZeros(cidr.Mask, net.IPv6len) {
			excludesIPv6 = true
		}
	}

	return excludesIPv4 && excludesIPv6
}

func isBufferAllZeros(buf []byte, length int) bool {
	if length > len(buf) {
		return false
	}
	for i := 0; i < length; i++ {
		if buf[i] != 0 {
			return false
		}
	}
	return true
}

// The following code is adapted from:
// https://cs.opensource.google/go/go/+/refs/tags/go1.21.4:src/crypto/x509/parser.go (the parseNameConstraintsExtension function)
// https://go-review.googlesource.com/c/go/+/238362 (also tracked at https://github.com/golang/go/issues/15196)
//
// NOTE: If/when that proposed change (238362) becomes part of Go, it will be possible to retire the function below in favour of cert.PermittedDirNames.

func permittedDirNames(cert *x509.Certificate) []pkix.RDNSequence {
	var dirNames []pkix.RDNSequence
	var oidNameConstraints = asn1.ObjectIdentifier{2, 5, 29, 30}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidNameConstraints) {
			outer := cryptobyte.String(ext.Value)
			var toplevel, permitted, excluded cryptobyte.String
			var havePermitted, haveExcluded bool
			if !outer.ReadASN1(&toplevel, cryptobyte_asn1.SEQUENCE) ||
				!outer.Empty() ||
				!toplevel.ReadOptionalASN1(&permitted, &havePermitted, cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) ||
				!toplevel.ReadOptionalASN1(&excluded, &haveExcluded, cryptobyte_asn1.Tag(1).ContextSpecific().Constructed()) ||
				!toplevel.Empty() {
				return nil // Invalid NameConstraints extension.
			}
			if !havePermitted || len(permitted) == 0 {
				return nil // No permittedSubtrees.
			}

			for !permitted.Empty() {
				var seq, value cryptobyte.String
				var tag cryptobyte_asn1.Tag
				if !permitted.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) ||
					!seq.ReadAnyASN1(&value, &tag) {
					return nil // Invalid NameConstraints extension.
				}

				var dirNameTag = cryptobyte_asn1.Tag(4).ContextSpecific().Constructed()
				switch tag {
				case dirNameTag:
					var dirName pkix.RDNSequence

					if rest, err := asn1.Unmarshal(value, &dirName); err != nil {
						return nil // ASN.1 decode error.
					} else if len(rest) != 0 {
						return nil // Trailing data after dirname constraint.
					}

					dirNames = append(dirNames, dirName)
				}
			}
		}
	}

	return dirNames
}
