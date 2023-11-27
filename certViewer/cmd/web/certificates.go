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
	"strings"
	"time"
)

type Certificate struct {
	Serial                 string
	Version                int
	SignatureAlgorithm     string
	Issuer                 pkix.Name
	Validity               Validity
	Subject                pkix.Name
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

func certInfo(cert *x509.Certificate) Certificate {
	serial, err := GetHexASN1Serial(cert)
	if err != nil {
		slog.Error("Unable to retrieve ASN1 serial", "error", err.Error())
	}

	certRead := Certificate{
		Version: cert.Version,
		Serial:  serial,
		Subject: cert.Subject,
		Issuer:  cert.Issuer,
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
