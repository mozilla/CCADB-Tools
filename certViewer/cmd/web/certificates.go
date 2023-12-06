/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* Some of the following code is adapted from:
* https://github.com/mozilla/tls-observatory/blob/7bc42856d2e5594614b56c2f55baf42bb9751b3d/certificate/certificate.go */

package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type Certificate struct {
	Serial                 string
	Version                int
	SignatureAlgorithm     string
	Issuer                 string
	Validity               Validity
	Subject                string
	Key                    SubjectPublicKeyInfo
	X509v3Extensions       Extensions
	X509v3BasicConstraints string
	CA                     bool
	Hashes                 Hashes
	Raw                    string
}

type Hashes struct {
	SHA1              string
	SHA256            string
	SPKISHA256        string
	SubjectSPKISHA256 string
	PKPSHA256         string
}

type Validity struct {
	NotBefore string
	NotAfter  string
}

type Subject struct {
	Country                     []string
	Organization                []string
	OrganizationalUnit          []string
	CommonName                  string
	Locality                    []string
	StateOrProvince             []string
	StreetAddress               []string
	PostalCode                  []string
	SerialNumber                string
	EmailAddress                any
	UID                         any
	DomainComponent             []string
	Name                        any
	Surname                     any
	GivenName                   any
	Initials                    any
	GenerationQualifier         any
	Title                       any
	Pseudonym                   any
	BusinessCategory            any
	JurisdictionLocality        any
	JurisdictionStateOrProvince any
	JurisdictionCountry         any
	OrganizationIdentifier      any
	DNQualifier                 any
}

type SubjectPublicKeyInfo struct {
	Alg      string
	Size     float64
	Exponent float64
	X        string
	Y        string
	P        string
	Q        string
	G        string
	Curve    string
}

// Extensions that are already decoded in the x509 Certificate structure
type Extensions struct {
	AuthorityKeyId         string
	SubjectKeyId           string
	KeyUsage               string
	ExtendedKeyUsage       string
	ExtendedKeyUsageOID    string
	SubjectAlternativeName []string
	CRLDistributionPoints  string
	PolicyIdentifiers      string
	PermittedDNSDomains    string
	PermittedIPAddresses   string
	ExcludedDNSDomains     string
	ExcludedIPAddresses    string
	InhibitAnyPolicy       *int
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
	"SHA256WithRSAPSS",
	"SHA384WithRSAPSS",
	"SHA512WithRSAPSS",
	"PureEd25519",
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

// OIDFieldName takes in an OID asn1.ObjectIdentifier and returns the field name
// This is where we can add additional OIDs and fields that Go doesn't support natively
func OIDFieldName(oid asn1.ObjectIdentifier) string {
	switch oid.String() {
	case "2.5.29.54":
		return "InhibitAnyPolicy"
	default:
		return ""
	}
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
		KeyUsage:               strings.Join(getKeyUsages(cert), ", "),
		ExtendedKeyUsage:       strings.Join(getExtKeyUsages(cert), ", "),
		ExtendedKeyUsageOID:    strings.Join(getExtKeyUsageOIDs(cert), ", "),
		PolicyIdentifiers:      strings.Join(getPolicyIdentifiers(cert), ", "),
		SubjectAlternativeName: san,
		CRLDistributionPoints:  strings.Join(crld, ", "),
		PermittedDNSDomains:    strings.Join(constraints.PermittedDNSDomains, ", "),
		ExcludedDNSDomains:     strings.Join(constraints.ExcludedDNSDomains, ", "),
		PermittedIPAddresses:   strings.Join(permittedIPAddresses, ", "),
		ExcludedIPAddresses:    strings.Join(excludedIPAddresses, ", "),
	}

	for _, v := range cert.Extensions {
		if OIDFieldName(v.Id) == "InhibitAnyPolicy" {
			value, _ := strconv.Atoi(string(v.Value))
			ext.InhibitAnyPolicy = &value
		}
	}

	return ext
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

// GetOIDAttributes retrieves field names for OIDs that Go does not natively support
func GetOIDAttributes(attributes []pkix.AttributeTypeAndValue) Subject {
	var (
		subjectAttributes Subject
		domainComponents  []string
	)

	for _, v := range attributes {
		switch v.Type.String() {
		case "1.2.840.113549.1.9.1":
			subjectAttributes.EmailAddress = v.Value
		case "0.9.2342.19200300.100.1.1":
			subjectAttributes.UID = v.Value
		case "2.5.4.41":
			subjectAttributes.Name = v.Value
		case "2.5.4.4":
			subjectAttributes.Surname = v.Value
		case "2.5.4.42":
			subjectAttributes.GivenName = v.Value
		case "2.5.4.43":
			subjectAttributes.Initials = v.Value
		case "2.5.4.44":
			subjectAttributes.GenerationQualifier = v.Value
		case "2.5.4.12":
			subjectAttributes.Title = v.Value
		case "2.5.4.65":
			subjectAttributes.Pseudonym = v.Value
		case "2.5.4.15":
			subjectAttributes.BusinessCategory = v.Value
		case "1.3.6.1.4.1.311.60.2.1.1":
			subjectAttributes.JurisdictionLocality = v.Value
		case "1.3.6.1.4.1.311.60.2.1.2":
			subjectAttributes.JurisdictionStateOrProvince = v.Value
		case "1.3.6.1.4.1.311.60.2.1.3":
			subjectAttributes.JurisdictionCountry = v.Value
		case "2.5.4.97":
			subjectAttributes.OrganizationIdentifier = v.Value
		case "2.5.4.46":
			subjectAttributes.DNQualifier = v.Value
		case "0.9.2342.19200300.100.1.25":
			domainComponents = append(domainComponents, v.Value.(string))
		}
	}

	subjectAttributes.DomainComponent = domainComponents

	return subjectAttributes
}

// GetAttributes takes a Subject struct and returns all fields in a comma-delimited string
func GetAttributes(attributes Subject) string {
	var attr []string

	if len(attributes.Country) > 0 {
		attr = append(attr, "C="+strings.Join(attributes.Country, ", C="))
	}
	if len(attributes.Organization) > 0 {
		attr = append(attr, "O="+strings.Join(attributes.Organization, ", O="))
	}
	if len(attributes.OrganizationalUnit) > 0 {
		attr = append(attr, "OU="+strings.Join(attributes.OrganizationalUnit, ", OU="))
	}
	if len(attributes.Locality) > 0 {
		attr = append(attr, "L="+strings.Join(attributes.Locality, ", L="))
	}
	if len(attributes.StateOrProvince) > 0 {
		attr = append(attr, "ST="+strings.Join(attributes.StateOrProvince, ", ST="))
	}
	if len(attributes.StreetAddress) > 0 {
		attr = append(attr, "streetAddress="+strings.Join(attributes.StreetAddress, ", streetAddress="))
	}
	if len(attributes.PostalCode) > 0 {
		attr = append(attr, "postalCode="+strings.Join(attributes.PostalCode, ", postalCode="))
	}
	if len(attributes.SerialNumber) > 0 {
		attr = append(attr, "SN="+attributes.SerialNumber)
	}
	if len(attributes.CommonName) > 0 {
		attr = append(attr, "CN="+attributes.CommonName)
	}
	if attributes.EmailAddress != nil && len(attributes.EmailAddress.(string)) > 0 {
		attr = append(attr, "emailAddress="+attributes.EmailAddress.(string))
	}
	if attributes.UID != nil && len(attributes.UID.(string)) > 0 {
		attr = append(attr, "UID="+attributes.UID.(string))
	}
	if attributes.DomainComponent != nil && len(attributes.DomainComponent) > 0 {
		attr = append(attr, "DC="+strings.Join(attributes.DomainComponent, ", DC="))
	}
	if attributes.Name != nil && len(attributes.Name.(string)) > 0 {
		attr = append(attr, "name="+attributes.Name.(string))
	}
	if attributes.Surname != nil && len(attributes.Surname.(string)) > 0 {
		attr = append(attr, "surname="+attributes.Surname.(string))
	}
	if attributes.GivenName != nil && len(attributes.GivenName.(string)) > 0 {
		attr = append(attr, "givenName="+attributes.GivenName.(string))
	}
	if attributes.Initials != nil && len(attributes.Initials.(string)) > 0 {
		attr = append(attr, "initials="+attributes.Initials.(string))
	}
	if attributes.GenerationQualifier != nil && len(attributes.GenerationQualifier.(string)) > 0 {
		attr = append(attr, "generationQualifier="+attributes.GenerationQualifier.(string))
	}
	if attributes.Title != nil && len(attributes.Title.(string)) > 0 {
		attr = append(attr, "title="+attributes.Title.(string))
	}
	if attributes.Pseudonym != nil && len(attributes.Pseudonym.(string)) > 0 {
		attr = append(attr, "pseudonym="+attributes.Pseudonym.(string))
	}
	if attributes.BusinessCategory != nil && len(attributes.BusinessCategory.(string)) > 0 {
		attr = append(attr, "businessCategory="+attributes.BusinessCategory.(string))
	}
	if attributes.JurisdictionLocality != nil && len(attributes.JurisdictionLocality.(string)) > 0 {
		attr = append(attr, "jurisdictionLocality="+attributes.JurisdictionLocality.(string))
	}
	if attributes.JurisdictionStateOrProvince != nil && len(attributes.JurisdictionStateOrProvince.(string)) > 0 {
		attr = append(attr, "jurisdictionStateOrProvince="+attributes.JurisdictionStateOrProvince.(string))
	}
	if attributes.JurisdictionCountry != nil && len(attributes.JurisdictionCountry.(string)) > 0 {
		attr = append(attr, "jurisdictionCountry="+attributes.JurisdictionCountry.(string))
	}
	if attributes.OrganizationIdentifier != nil && len(attributes.OrganizationIdentifier.(string)) > 0 {
		attr = append(attr, "organizationIdentifier="+attributes.OrganizationIdentifier.(string))
	}
	if attributes.DNQualifier != nil && len(attributes.DNQualifier.(string)) > 0 {
		attr = append(attr, "dnQualifier="+attributes.DNQualifier.(string))
	}

	return strings.Join(attr, ", ")
}

// CertInfo returns a Certificate struct created from a X509.Certificate
func certInfo(cert *x509.Certificate) Certificate {
	serial, err := GetHexASN1Serial(cert)
	if err != nil {
		slog.Error("Unable to retrieve ASN1 serial", "error", err.Error())
	}

	certRead := Certificate{
		Version: cert.Version,
		Serial:  serial,
		Validity: Validity{
			NotBefore: cert.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:  cert.NotAfter.UTC().Format(time.RFC3339),
		},
		SignatureAlgorithm: SignatureAlgorithm[cert.SignatureAlgorithm],
		Hashes: Hashes{
			SHA1:              SHA1Hash(cert.Raw),
			SHA256:            SHA256Hash(cert.Raw),
			SPKISHA256:        SPKISHA256(cert),
			SubjectSPKISHA256: SubjectSPKISHA256(cert),
			PKPSHA256:         PKPSHA256Hash(cert),
		},
		CA:  cert.IsCA,
		Raw: base64.StdEncoding.EncodeToString(cert.Raw),
	}

	certRead.Key, err = getPublicKeyInfo(cert)
	if err != nil {
		slog.Error("Failed to retrieve public key information", "error", err.Error())
	}

	// Handle common attributes for Issuer
	var commonIssuerAttributes Subject
	commonIssuerAttributes.Country = cert.Issuer.Country
	commonIssuerAttributes.Organization = cert.Issuer.Organization
	commonIssuerAttributes.OrganizationalUnit = cert.Issuer.OrganizationalUnit
	commonIssuerAttributes.Locality = cert.Issuer.Locality
	commonIssuerAttributes.StateOrProvince = cert.Issuer.Province
	commonIssuerAttributes.StreetAddress = cert.Issuer.StreetAddress
	commonIssuerAttributes.PostalCode = cert.Issuer.PostalCode
	commonIssuerAttributes.SerialNumber = cert.Issuer.SerialNumber
	commonIssuerAttributes.CommonName = cert.Issuer.CommonName
	// Handle uncommon attributes for Issuer
	uncommonIssuerAttributes := GetOIDAttributes(cert.Issuer.Names)
	// Format all Issuer attributes into one string
	// If uncommon attributes are empty, only return common... otherwise we get a trailing comma
	if reflect.DeepEqual(uncommonIssuerAttributes, Subject{}) {
		certRead.Issuer = GetAttributes(commonIssuerAttributes)
	} else {
		certRead.Issuer = strings.Join([]string{GetAttributes(commonIssuerAttributes), GetAttributes(uncommonIssuerAttributes)}, ", ")
	}

	// Handle common attributes for Subject
	var commonSubjectAttributes Subject
	commonSubjectAttributes.Country = cert.Subject.Country
	commonSubjectAttributes.Organization = cert.Subject.Organization
	commonSubjectAttributes.OrganizationalUnit = cert.Subject.OrganizationalUnit
	commonSubjectAttributes.Locality = cert.Subject.Locality
	commonSubjectAttributes.StateOrProvince = cert.Subject.Province
	commonSubjectAttributes.StreetAddress = cert.Subject.StreetAddress
	commonSubjectAttributes.PostalCode = cert.Subject.PostalCode
	commonSubjectAttributes.SerialNumber = cert.Subject.SerialNumber
	commonSubjectAttributes.CommonName = cert.Subject.CommonName
	// Handle uncommon attributes for Subject
	uncommonSubjectAttributes := GetOIDAttributes(cert.Subject.Names)
	// Format all Subject attributes into one string
	// If uncommon attributes are empty, only return common... otherwise we get a trailing comma
	if reflect.DeepEqual(uncommonSubjectAttributes, Subject{}) {
		certRead.Subject = GetAttributes(commonSubjectAttributes)
	} else {
		certRead.Subject = strings.Join([]string{GetAttributes(commonSubjectAttributes), GetAttributes(uncommonSubjectAttributes)}, ", ")
	}

	certRead.X509v3Extensions = getCertExtensions(cert)

	return certRead
}

// certCleanup removes the cert submitted after ev-checker runs to keep things tidy
func (app *application) certCleanup(pemFile string) {
	err := os.RemoveAll(pemFile)
	if err != nil {
		app.logger.Error("Unable to delete PEM files or directories", "Error", err.Error())
	} else {
		app.logger.Info("Removed unused PEM file", "File", pemFile)
	}
}
