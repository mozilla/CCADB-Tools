/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package ccadb

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"encoding/pem"
	"fmt"
	"github.com/mozilla/CCADB-Tools/capi/lib/certificateUtils"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"net/http"
)

const ReportURL = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV"

var headers = []string{"Owner", "Certificate Issuer Organization", "Certificate Issuer Organizational Unit", "Common Name or Certificate Name", "Certificate Serial Number", "SHA-256 Fingerprint", "Subject + SPKI SHA256", "Valid From [GMT]", "Valid To [GMT]", "Public Key Algorithm", "Signature Hash Algorithm", "Trust Bits", "Distrust for TLS After Date", "Distrust for S/MIME After Date", "EV Policy OID(s)", "Approval Bug", "NSS Release When First Included", "Firefox Release When First Included", "Test Website - Valid", "Test Website - Expired", "Test Website - Revoked", "Mozilla Applied Constraints", "Company Website", "Geographic Focus", "Certificate Policy (CP)", "Certification Practice Statement (CPS)", "Standard Audit", "BR Audit", "EV Audit", "Auditor", "Standard Audit Type", "Standard Audit Statement Dt", "PEM Info"}

const (
	Owner = iota
	CertificateIssuerOrganization
	CertificateIssuerOrganizationalUnit
	CommonNameorCertificateName
	CertificateSerialNumber
	SHA256Fingerprint
	SubjectSPKISHA256
	ValidFromGMT
	ValidToGMT
	PublicKeyAlgorithm
	SignatureHashAlgorithm
	TrustBits
	DistrustForTLSAfterDate
	DistrustForSMIMEAfterDate
	EVPolicyOIDs
	ApprovalBug
	NSSReleaseWhenFirstIncluded
	FirefoxReleaseWhenFirstIncluded
	TestWebsiteValid
	TestWebsiteExpired
	TestWebsiteRevoked
	MozillaAppliedConstraints
	CompanyWebsite
	GeographicFocus
	CertificatePolicyCP
	CertificationPracticeStatementCPS
	StandardAudit
	BRAudit
	EVAudit
	Auditor
	StandardAuditType
	StandardAuditStatementDt
	PEMInfo
)

type Report struct {
	Records []Record
}

type Record []string

func (r Record) Root() *x509.Certificate {
	block, _ := pem.Decode([]byte(r.RootPEM()))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logrus.Panic(err)
	}
	return cert
}

func (r Record) RootPEM() string {
	pem, err := certificateUtils.NormalizePEM([]byte(r[PEMInfo]))
	if err != nil {
		logrus.Panic(err)
	}
	return string(pem)
}

func (r Record) TestWebsiteValid() string {
	return r[TestWebsiteValid]
}

func (r Record) TestWebsiteExpired() string {
	return r[TestWebsiteExpired]
}

func (r Record) TestWebsiteRevoked() string {
	return r[TestWebsiteRevoked]
}

func (r Record) Fingerprint() string {
	return r[SHA256Fingerprint]
}

func NewReport() (Report, error) {
	return NewReportFrom(ReportURL)
}

func NewReportFrom(url string) (report Report, err error) {
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: transport}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Add("X-TOOL", "github.com/christopher-henderson/capi")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logrus.Warn(err)
		}
	}()
	c := csv.NewReader(resp.Body)
	all, err := c.ReadAll()
	if err != nil {
		return
	}
	err = assertHeader(all[0])
	if err != nil {
		return
	}
	report.Records = make([]Record, len(all[1:]))
	for i, r := range all[1:] {
		report.Records[i] = r
	}
	return
}

func assertHeader(header []string) error {
	for i, field := range header {
		if field != headers[i] {
			return errors.New(fmt.Sprintf("Unexpected CSV header. Wanted %s, got %s", headers, header))
		}
	}
	return nil
}
