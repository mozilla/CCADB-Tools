/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package ccadb

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"log"
	"strings"
	"time"

	"github.com/mozilla/CCADB-Tools/certdataDiffCCADB/utils"
)

const (
	URL = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV"

	IntermediateReportURL = "https://ccadb.my.salesforce-sites.com/mozilla/PublicAllInterCertsIncTechConsWithPEMCSV"
	RootReportURL         = "http://ccadb.my.salesforce-sites.com/mozilla/PEMDataForRootCertsWithPEMCSV"

	PEMInfo                             = "PEM Info"
	SHA1Fingerprint                     = "SHA-1 Fingerprint"
	SHA256Fingerprint                   = "SHA-256 Fingerprint"
	CertificateID                       = "Certificate ID"
	CertificateIssuerCommonName         = "Certificate Issuer Common Name"
	CertificateIssuerOrganization       = "Certificate Issuer Organization"
	CertificateIssuerOrganizationalUnit = "Certificate Issuer Organizational Unit"
	PublicKeyAlgorithm                  = "Public Key Algorithm"
	CertificateSerialNumber             = "Certificate Serial Number"
	SignatureHashAlgorithm              = "Signature Hash Algorithm"
	CertificateSubjectCommonName        = "Certificate Subject Common Name"
	CertificateSubjectOrganization      = "Certificate Subject Organization"
	CertificateSubjectOrganizationUnit  = "Certificate Subject Organization Unit"
	ValidFromGMT                        = "Valid From [GMT]"
	ValidToGMT                          = "Valid To [GMT]"
	CRLURLs                             = "CRL URL(s)"
	ExtendedKeyUsage                    = "Extended Key Usage"
	TechnicallyConstrained              = "Technically Constrained"

	CAOwner             = "CA Owner"
	RootCertificateName = "Root Certificate Name"
	Subject             = "Subject"

	CIO  = CertificateIssuerOrganization
	CIOU = CertificateIssuerOrganizationalUnit
	CN   = "Common Name or Certificate Name"
	CSN  = CertificateSerialNumber
	FP   = SHA256Fingerprint
	PEM  = PEMInfo
	TB   = "Trust Bits"

	TimeFMT = "2006 Jan 02"

	TrustWeb   = "Websites"
	TrustEmail = "Email"
)

type Certificate struct {
	columnMap map[string]int
	row       []string
	lineNum   int
}

func (c *Certificate) Set(key, value string) {
	if i, ok := c.columnMap[key]; ok {
		c.row[i] = value
	} else {
		c.row = append(c.row, value)
		c.columnMap[key] = len(c.row) - 1
	}
}

func (c *Certificate) Get(attr string) (string, bool) {
	index, ok := c.columnMap[attr]
	if !ok {
		return "", false
	}
	return c.row[index], true
}

func (c *Certificate) Keys() []string {
	keys := make([]string, len(c.columnMap))
	i := 0
	for k, _ := range c.columnMap {
		keys[i] = k
		i++
	}
	return keys
}

func (c *Certificate) GetOrPanic(attr string) string {
	value, ok := c.Get(attr)
	if !ok {
		switch {
		// Roots are trusted apriori, and thus do not have
		// a CRL that can be authoritative about them. As such
		// we don't panic on fields that roots don't have.
		case attr == CRLURLs, attr == ExtendedKeyUsage, attr == TechnicallyConstrained:
			// This is not a local design decision. This is what the CCADB presents
			// in a query instead of a null value.
			return "(not present)"
		}
		log.Panicf("Failed to retrieve attribute %v.\n Available attributes are: %v", attr, c.Keys())
	}
	return value
}

func (c *Certificate) ValidFromGMT() (time.Time, error) {
	t, ok := c.Get(ValidFromGMT)
	if !ok {
		return time.Time{}, errors.New("ValidFromGMT not found.")
	}
	return time.Parse(TimeFMT, t)
}

func (c *Certificate) ValidToGMT() (time.Time, error) {
	t, ok := c.Get(ValidToGMT)
	if !ok {
		return time.Time{}, errors.New("ValidToGMT not found.")
	}
	return time.Parse(TimeFMT, t)
}

func (c *Certificate) MarshalJSON() ([]byte, error) {
	m := make(map[string]string)
	for key, v := range c.columnMap {
		m[key] = c.row[v]
	}
	return json.MarshalIndent(m, "", "    ")
}

func NewCertificate(columnMap map[string]int, row []string, lineNum int) *Certificate {
	p := row[columnMap["PEM Info"]]
	row[columnMap["PEM Info"]] = p[1 : len(p)-1]
	return &Certificate{columnMap, row, lineNum}
}

// NewEntry attempts to build a certdataDiffCCADb.Entry from a provided CCADB certificate.
func NewEntry(c *Certificate) *utils.Entry {
	var cio string
	var ciou string
	var cn string
	var csn string
	var pem string
	var fp string
	var tb string
	var tw bool
	var te bool
	var ok bool
	if cio, ok = c.Get(CIO); !ok {
		log.Printf("Failed to find column in CCADB, %v\n", CIO)
	}
	if ciou, ok = c.Get(CIOU); !ok {
		log.Printf("Failed to find column in CCADB, %v\n", CIOU)
	}
	if cn, ok = c.Get(CN); !ok {
		log.Printf("Failed to find column in CCADB, %v\n", CN)
	}
	if csn, ok = c.Get(CSN); !ok {
		log.Printf("Failed to find column in CCADB, %v\n", CSN)
	}
	if pem, ok = c.Get(PEM); !ok {
		log.Printf("Failed to find column in CCADB, %v\n", PEM)
	}
	if fp, ok = c.Get(FP); !ok {
		log.Printf("Failed to find column in CCADB, %v\n", FP)
	}
	if tb, ok = c.Get(TB); !ok {
		log.Printf("Failed to find column in CCADB, %v\n", TB)
	}
	tw, te = strings.Contains(tb, TrustWeb), strings.Contains(tb, TrustEmail)
	return utils.NewEntry(cio, ciou, cn, csn, pem, fp, tw, te,
		c.lineNum, "ccadb")
}

func ParseToNormalizedForm(stream io.Reader) ([]*utils.Entry, error) {
	records, err := Parse(stream)
	if err != nil {
		return nil, err
	}
	entries := make([]*utils.Entry, len(records))
	for i, record := range records {
		entries[i] = NewEntry(record)
	}
	return entries, nil
}

func Parse(stream io.Reader) ([]*Certificate, error) {
	records := make([]*Certificate, 0)
	reader := csv.NewReader(stream)
	columnMap := make(map[string]int)
	columns, err := reader.Read()
	if err != nil {
		return records, err
	}
	// Extract column headers from the first row so we don't have to
	// hardcode the column numbers
	for index, attr := range columns {
		columnMap[attr] = index
	}
	lineNum := 1
	for row, err := reader.Read(); err == nil; row, err = reader.Read() {
		lineNum += 1
		records = append(records, NewCertificate(columnMap, row, lineNum))
		lineNum += strings.Count(strings.Join(row, ""), "\n")
	}
	return records, nil
}
