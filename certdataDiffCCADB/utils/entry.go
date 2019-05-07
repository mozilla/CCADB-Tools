/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package utils

import (
	"fmt"
	"regexp"
	"strings"
)

// Certificate normalization constants.
const (
	BEGIN = "-----BEGIN CERTIFICATE-----\n"
	END   = "-----END CERTIFICATE-----"
	WIDTH = 64 // Columns per line https://tools.ietf.org/html/rfc1421
)

var stripper *regexp.Regexp

func init() {
	stripper = regexp.MustCompile("('|'|\n|-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----)")
}

// Entry is a normalized form of a Certificate Authority found
// in either certdata.txt or from a CCADB report CSV.
type Entry struct {
	OrganizationName       string `json:"organizationName"`
	OrganizationalUnitName string `json:"organizationalUnitName"`
	CommonName             string `json:"commonName"`
	SerialNumber           string `json:"serialNumber"`
	PEM                    string `json:"-"`
	Fingerprint            string `json:"sha256"`
	TrustWeb               bool   `json:"trustWeb"`
	TrustEmail             bool   `json:"trustEmail"`
	LineNumber             int    `json:"lineNumber"`
	Origin                 string `json:"origin"`
}

// UniqueID returns the issuer distinguished name and the serial (noralized with no leading zeroes)
// contatenated together.
func (e *Entry) UniqueID() string {
	return fmt.Sprintf("%v%v", e.DistinguishedName(), e.NormalizedSerial())
}

// DistinguishedName builds a hierarchical string of Organization, Orgizational Unit, and Common Name.
func (e *Entry) DistinguishedName() string {
	return fmt.Sprintf("O=%v/OU=%v/CN=%v", e.OrganizationName, e.OrganizationalUnitName, e.CommonName)
}

// NormalizedSerial returns the serial number with any leading zeroes stripped off.
func (e *Entry) NormalizedSerial() string {
	return strings.TrimLeft(e.SerialNumber, "0")
}

// NewEntry constructs a new Entry with a normalized PEM.
func NewEntry(org, orgUnit, commonName, serial, pem, fingerprint string, trustWeb, trustEmail bool, line int, origin string) *Entry {
	return &Entry{org, orgUnit, commonName, serial, NormalizePEM(pem), fingerprint, trustWeb, trustEmail, line, origin}
}

// normalizePEM ignores any formatting or string artifacts that the PEM may have had
// and applies https://tools.ietf.org/html/rfc1421
//
// This stemmed from noticing that CCADB reports were fully formed while certdata
// PEMS had no formatting nor BEGIN/END fields. This is simply avoiding any surprises
// in individual formatting choices by forcing both to strip all formatting and conform
// to the one, chosen, way.
func NormalizePEM(pem string) string {
	if len(pem) == 0 {
		return ""
	}
	pem = stripper.ReplaceAllString(pem, "")
	p := []byte(pem)
	fmted := []byte(BEGIN)
	width := WIDTH
	for len(p) > 0 {
		if len(p) < WIDTH {
			width = len(p)
		}
		fmted = append(fmted, p[:width]...)
		fmted = append(fmted, '\n')
		p = p[width:]
	}
	fmted = append(fmted, END...)
	return string(fmted)
}
