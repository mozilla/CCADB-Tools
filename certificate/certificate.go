/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* The following code is adapted from code from:
* https://github.com/mozilla/tls-observatory/blob/7bc42856d2e5594614b56c2f55baf42bb9751b3d/certificate/certificate.go */

package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

type Certificate struct {
	Serial                 string               `json:"serialNumber"`
	ScanTarget             string               `json:"scanTarget,omitempty"`
	IPs                    []string             `json:"ips,omitempty"`
	Version                int                  `json:"version"`
	SignatureAlgorithm     string               `json:"signatureAlgorithm"`
	Issuer                 Subject              `json:"issuer"`
	Validity               Validity             `json:"validity"`
	Subject                Subject              `json:"subject"`
	Key                    SubjectPublicKeyInfo `json:"key"`
	X509v3Extensions       Extensions           `json:"x509v3Extensions"`
	X509v3BasicConstraints string               `json:"x509v3BasicConstraints"`
	CA                     bool                 `json:"ca"`
	Analysis               interface{}          `json:"analysis,omitempty"` //for future use...
	FirstSeenTimestamp     time.Time            `json:"firstSeenTimestamp"`
	LastSeenTimestamp      time.Time            `json:"lastSeenTimestamp"`
	Hashes                 Hashes               `json:"hashes"`
	Raw                    string               `json:"Raw"`
	Anomalies              string               `json:"anomalies,omitempty"`
	MozillaPolicyV25       MozillaPolicy        `json:"mozillaPolicyV2_5"`
}

type MozillaPolicy struct {
	IsTechnicallyConstrained bool
}

type Hashes struct {
	SHA1              string `json:"sha1,omitempty"`
	SHA256            string `json:"sha256,omitempty"`
	SPKISHA256        string `json:"spki-sha256,omitempty"`
	SubjectSPKISHA256 string `json:"subject-spki-sha256,omitempty"`
	PKPSHA256         string `json:"pin-sha256,omitempty"`
}

type Validity struct {
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
}

type Subject struct {
	ID           int64    `json:"id,omitempty"`
	Country      []string `json:"c,omitempty"`
	Organisation []string `json:"o,omitempty"`
	OrgUnit      []string `json:"ou,omitempty"`
	CommonName   string   `json:"cn,omitempty"`
}

type SubjectPublicKeyInfo struct {
	Alg      string  `json:"alg,omitempty"`
	Size     float64 `json:"size,omitempty"`
	Exponent float64 `json:"exponent,omitempty"`
	X        string  `json:"x,omitempty"`
	Y        string  `json:"y,omitempty"`
	P        string  `json:"p,omitempty"`
	Q        string  `json:"q,omitempty"`
	G        string  `json:"g,omitempty"`
	Curve    string  `json:"curve,omitempty"`
}

// Extensions that are already decoded in the x509 Certificate structure
type Extensions struct {
	AuthorityKeyId         string   `json:"authorityKeyId"`
	SubjectKeyId           string   `json:"subjectKeyId"`
	KeyUsage               []string `json:"keyUsage"`
	ExtendedKeyUsage       []string `json:"extendedKeyUsage"`
	ExtendedKeyUsageOID    []string `json:"extendedKeyUsageOID"`
	SubjectAlternativeName []string `json:"subjectAlternativeName"`
	CRLDistributionPoints  []string `json:"crlDistributionPoint"`
	PolicyIdentifiers      []string `json:"policyIdentifiers,omitempty"`
	PermittedDNSDomains    []string `json:"permittedDNSNames,omitempty"`
	PermittedIPAddresses   []string `json:"permittedIPAddresses,omitempty"`
	ExcludedDNSDomains     []string `json:"excludedDNSNames,omitempty"`
	ExcludedIPAddresses    []string `json:"excludedIPAddresses,omitempty"`
}

var SignatureAlgorithm = [...]string{
	"UnknownSignatureAlgorithm",
	"MD2WithRSA",
	"MD5WithRSA",
	"SHA1WithRSA",
	"SHA256WithRSA",
	"SHA384WithRSA",
	"SHA512WithRSA",
	"DSAWithSHA1",
	"DSAWithSHA256",
	"ECDSAWithSHA1",
	"ECDSAWithSHA256",
	"ECDSAWithSHA384",
	"ECDSAWithSHA512",
}

var ExtKeyUsage = [...]string{
	"ExtKeyUsageAny",
	"ExtKeyUsageServerAuth",
	"ExtKeyUsageClientAuth",
	"ExtKeyUsageCodeSigning",
	"ExtKeyUsageEmailProtection",
	"ExtKeyUsageIPSECEndSystem",
	"ExtKeyUsageIPSECTunnel",
	"ExtKeyUsageIPSECUser",
	"ExtKeyUsageTimeStamping",
	"ExtKeyUsageOCSPSigning",
	"ExtKeyUsageMicrosoftServerGatedCrypto",
	"ExtKeyUsageNetscapeServerGatedCrypto",
	"ExtKeyUsageMicrosoftCommercialCodeSigning",
	"ExtKeyUsageMicrosoftKernelCodeSigning",
}

var ExtKeyUsageOID = [...]string{
	asn1.ObjectIdentifier{2, 5, 29, 37, 0}.String(),                 // ExtKeyUsageAny
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}.String(),       // ExtKeyUsageServerAuth
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}.String(),       // ExtKeyUsageClientAuth
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}.String(),       // ExtKeyUsageCodeSigning
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}.String(),       // ExtKeyUsageEmailProtection
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}.String(),       // ExtKeyUsageIPSECEndSystem
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}.String(),       // ExtKeyUsageIPSECTunnel
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}.String(),       // ExtKeyUsageIPSECUser
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}.String(),       // ExtKeyUsageTimeStamping
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}.String(),       // ExtKeyUsageOCSPSigning
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}.String(), // ExtKeyUsageMicrosoftServerGatedCrypto
	asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}.String(),     // ExtKeyUsageNetscapeServerGatedCrypto
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}.String(), // ExtKeyUsageMicrosoftCommercialCodeSigning
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}.String(), // ExtKeyUsageMicrosoftKernelCodeSigning
}

var PublicKeyAlgorithm = [...]string{
	"UnknownPublicKeyAlgorithm",
	"RSA",
	"DSA",
	"ECDSA",
}

func SubjectSPKISHA256(cert *x509.Certificate) string {
	h := sha256.New()
	h.Write(cert.RawSubject)
	h.Write(cert.RawSubjectPublicKeyInfo)
	return fmt.Sprintf("%X", h.Sum(nil))
}

func SPKISHA256(cert *x509.Certificate) string {
	h := sha256.New()
	h.Write(cert.RawSubjectPublicKeyInfo)
	return fmt.Sprintf("%X", h.Sum(nil))
}

func PKPSHA256Hash(cert *x509.Certificate) string {
	h := sha256.New()
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey:
		der, _ := x509.MarshalPKIXPublicKey(pub)
		h.Write(der)
	default:
		return ""
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func SHA256Hash(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%X", h[:])
}

func SHA1Hash(data []byte) string {
	h := sha1.Sum(data)
	return fmt.Sprintf("%X", h[:])
}

func getExtKeyUsages(cert *x509.Certificate) []string {
	usage := make([]string, 0)
	for _, eku := range cert.ExtKeyUsage {
		usage = append(usage, ExtKeyUsage[eku])
	}
	for _, unknownEku := range cert.UnknownExtKeyUsage {
		usage = append(usage, unknownEku.String())
	}
	return usage
}

func getExtKeyUsageOIDs(cert *x509.Certificate) []string {
	usage := make([]string, 0)
	for _, eku := range cert.ExtKeyUsage {
		usage = append(usage, ExtKeyUsageOID[eku])
	}
	for _, unknownEku := range cert.UnknownExtKeyUsage {
		usage = append(usage, unknownEku.String())
	}
	return usage
}

func getPolicyIdentifiers(cert *x509.Certificate) []string {
	identifiers := make([]string, 0)
	for _, pi := range cert.PolicyIdentifiers {
		identifiers = append(identifiers, pi.String())
	}
	return identifiers
}

func getKeyUsages(cert *x509.Certificate) []string {
	usage := make([]string, 0)
	keyUsage := cert.KeyUsage

	//calculate included keyUsage from bitmap
	//String values taken from OpenSSL

	if keyUsage&x509.KeyUsageDigitalSignature != 0 {
		usage = append(usage, "Digital Signature")
	}
	if keyUsage&x509.KeyUsageContentCommitment != 0 {
		usage = append(usage, "Non Repudiation")
	}

	if keyUsage&x509.KeyUsageKeyEncipherment != 0 {
		usage = append(usage, "Key Encipherment")
	}

	if keyUsage&x509.KeyUsageDataEncipherment != 0 {
		usage = append(usage, "Data Encipherment")
	}

	if keyUsage&x509.KeyUsageKeyAgreement != 0 {
		usage = append(usage, "Key Agreement")
	}

	if keyUsage&x509.KeyUsageCertSign != 0 {
		usage = append(usage, "Certificate Sign")
	}

	if keyUsage&x509.KeyUsageCRLSign != 0 {
		usage = append(usage, "CRL Sign")
	}

	if keyUsage&x509.KeyUsageEncipherOnly != 0 {
		usage = append(usage, "Encipher Only")
	}

	if keyUsage&x509.KeyUsageDecipherOnly != 0 {
		usage = append(usage, "Decipher Only")
	}

	return usage
}

// getCertExtensions currently stores only the extensions that are already exported by GoLang
// (in the x509 Certificate Struct)
func getCertExtensions(cert *x509.Certificate) Extensions {
	// initialize []string to store them as `[]` instead of null
	san := make([]string, 0)
	san = append(san, cert.DNSNames...)
	crld := make([]string, 0)
	crld = append(crld, cert.CRLDistributionPoints...)
	constraints, _ := GetConstraints(cert)
	ipNetSliceToStringSlice := func(in []*net.IPNet) []string {
		out := make([]string, 0)
		for _, ipnet := range in {
			out = append(out, ipnet.String())
		}
		return out
	}
	permittedIPAddresses := ipNetSliceToStringSlice(constraints.PermittedIPRanges)
	excludedIPAddresses := ipNetSliceToStringSlice(constraints.ExcludedIPRanges)
	ext := Extensions{
		AuthorityKeyId:         base64.StdEncoding.EncodeToString(cert.AuthorityKeyId),
		SubjectKeyId:           base64.StdEncoding.EncodeToString(cert.SubjectKeyId),
		KeyUsage:               getKeyUsages(cert),
		ExtendedKeyUsage:       getExtKeyUsages(cert),
		ExtendedKeyUsageOID:    getExtKeyUsageOIDs(cert),
		PolicyIdentifiers:      getPolicyIdentifiers(cert),
		SubjectAlternativeName: san,
		CRLDistributionPoints:  crld,
		PermittedDNSDomains:    constraints.PermittedDNSDomains,
		ExcludedDNSDomains:     constraints.ExcludedDNSDomains,
		PermittedIPAddresses:   permittedIPAddresses,
		ExcludedIPAddresses:    excludedIPAddresses,
	}
	return ext
}

func getMozillaPolicyV25(cert *x509.Certificate) MozillaPolicy {
	return MozillaPolicy{IsTechnicallyConstrained: IsTechnicallyConstrainedMozPolicyV25(cert)}
}

func getPublicKeyInfo(cert *x509.Certificate) (SubjectPublicKeyInfo, error) {
	pubInfo := SubjectPublicKeyInfo{
		Alg: PublicKeyAlgorithm[cert.PublicKeyAlgorithm],
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		pubInfo.Size = float64(pub.N.BitLen())
		pubInfo.Exponent = float64(pub.E)

	case *dsa.PublicKey:
		pubInfo.Size = float64(pub.Y.BitLen())
		textInt, err := pub.G.MarshalText()

		if err == nil {
			pubInfo.G = string(textInt)
		} else {
			return pubInfo, err
		}

		textInt, err = pub.P.MarshalText()

		if err == nil {
			pubInfo.P = string(textInt)
		} else {
			return pubInfo, err
		}

		textInt, err = pub.Q.MarshalText()

		if err == nil {
			pubInfo.Q = string(textInt)
		} else {
			return pubInfo, err
		}

		textInt, err = pub.Y.MarshalText()

		if err == nil {
			pubInfo.Y = string(textInt)
		} else {
			return pubInfo, err
		}

	case *ecdsa.PublicKey:
		pubInfo.Size = float64(pub.Curve.Params().BitSize)
		pubInfo.Curve = pub.Curve.Params().Name
		pubInfo.Y = pub.Y.String()
		pubInfo.X = pub.X.String()
	}

	return pubInfo, nil

}

func GetHexASN1Serial(cert *x509.Certificate) (serial string, err error) {
	m, err := asn1.Marshal(cert.SerialNumber)
	if err != nil {
		return
	}
	var rawValue asn1.RawValue
	_, err = asn1.Unmarshal(m, &rawValue)
	if err != nil {
		return
	}
	serial = fmt.Sprintf("%X", rawValue.Bytes)
	return
}

// CertToJSON returns a Certificate struct created from a X509.Certificate
func CertToJSON(cert *x509.Certificate) Certificate {
	var (
		domain   string
		ip       string
		err      error
		certJson = Certificate{}
	)
	// initialize []string to never store them as null
	certJson.IPs = make([]string, 0)

	certJson.Version = cert.Version

	// If there's an error, we just store the zero value ("")
	serial, _ := GetHexASN1Serial(cert)
	certJson.Serial = serial

	certJson.SignatureAlgorithm = SignatureAlgorithm[cert.SignatureAlgorithm]

	certJson.Key, err = getPublicKeyInfo(cert)
	if err != nil {
		log.Printf("Failed to retrieve public key information: %v. Continuing anyway.", err)
	}

	certJson.Issuer.Country = cert.Issuer.Country
	certJson.Issuer.Organisation = cert.Issuer.Organization
	certJson.Issuer.OrgUnit = cert.Issuer.OrganizationalUnit
	certJson.Issuer.CommonName = cert.Issuer.CommonName

	certJson.Subject.Country = cert.Subject.Country
	certJson.Subject.Organisation = cert.Subject.Organization
	certJson.Subject.OrgUnit = cert.Subject.OrganizationalUnit
	certJson.Subject.CommonName = cert.Subject.CommonName

	certJson.Validity.NotBefore = cert.NotBefore.UTC()
	certJson.Validity.NotAfter = cert.NotAfter.UTC()

	certJson.X509v3Extensions = getCertExtensions(cert)

	certJson.MozillaPolicyV25 = getMozillaPolicyV25(cert)

	//below check tries to hack around the basic constraints extension
	//not being available in versions < 3.
	//Only the IsCa variable is set, as setting X509v3BasicConstraints
	//messes up the validation procedure.
	if cert.Version < 3 {
		certJson.CA = cert.IsCA
	} else {
		if cert.BasicConstraintsValid {
			certJson.X509v3BasicConstraints = "Critical"
			certJson.CA = cert.IsCA
		} else {
			certJson.X509v3BasicConstraints = ""
			certJson.CA = false
		}
	}

	t := time.Now().UTC()

	certJson.FirstSeenTimestamp = t
	certJson.LastSeenTimestamp = t

	if !cert.IsCA {
		certJson.ScanTarget = domain
		certJson.IPs = append(certJson.IPs, ip)
	}

	certJson.Hashes.SHA1 = SHA1Hash(cert.Raw)
	certJson.Hashes.SHA256 = SHA256Hash(cert.Raw)
	certJson.Hashes.SPKISHA256 = SPKISHA256(cert)
	certJson.Hashes.SubjectSPKISHA256 = SubjectSPKISHA256(cert)
	certJson.Hashes.PKPSHA256 = PKPSHA256Hash(cert)

	certJson.Raw = base64.StdEncoding.EncodeToString(cert.Raw)

	return certJson
}

// ToX509 returns the crypto/x509 version of a certificate
func (cert Certificate) ToX509() (xcert *x509.Certificate, err error) {
	certRaw, err := base64.StdEncoding.DecodeString(cert.Raw)
	if err != nil {
		return
	}
	return x509.ParseCertificate(certRaw)
}

// String() prints the subject as a single string, following OpenSSL's display
// format: Subject: C=US, ST=California, L=Mountain View, O=Google Inc, CN=*.google.com
func (s Subject) String() string {
	var comp []string
	if len(s.Country) > 0 {
		comp = append(comp, "C="+strings.Join(s.Country, ", C="))
	}
	if len(s.Organisation) > 0 {
		comp = append(comp, "O="+strings.Join(s.Organisation, ", O="))
	}
	if len(s.OrgUnit) > 0 {
		comp = append(comp, "OU="+strings.Join(s.OrgUnit, ", OU="))
	}
	if len(s.CommonName) > 0 {
		comp = append(comp, "CN="+s.CommonName)
	}
	return strings.Join(comp, ", ")
}

// IsSelfSigned return true if the subject and issuer fields of a certificate
// are identical
func (cert Certificate) IsSelfSigned() bool {
	if cert.Subject.CommonName != cert.Issuer.CommonName ||
		len(cert.Subject.Organisation) != len(cert.Issuer.Organisation) ||
		len(cert.Subject.OrgUnit) != len(cert.Issuer.OrgUnit) ||
		len(cert.Subject.Country) != len(cert.Issuer.Country) {
		return false
	}
	for i := range cert.Subject.Organisation {
		if cert.Subject.Organisation[i] != cert.Issuer.Organisation[i] {
			return false
		}
	}
	for i := range cert.Subject.OrgUnit {
		if cert.Subject.OrgUnit[i] != cert.Issuer.OrgUnit[i] {
			return false
		}
	}
	for i := range cert.Subject.Country {
		if cert.Subject.Country[i] != cert.Issuer.Country[i] {
			return false
		}
	}
	return true
}
