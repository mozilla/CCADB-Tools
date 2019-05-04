/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package certdata

import (
	"bufio"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"github.com/mozilla/CCADB-Tools/certdataDiffCCADB/utils"
)

// Strings that mark the beginning of blocks of text important for parsing certdata.txt.
const (
	URL = "https://hg.mozilla.org/releases/mozilla-beta/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt"

	StartCertificate = "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE" // Declaration of start of Certificate object.
	StartTrust       = "CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST"   // Declaration of start of a Distrust object.

	WebDistrust = "CKA_TRUST_SERVER_AUTH CK_TRUST (CKT_NSS_MUST_VERIFY_TRUST|CKT_NSS_NOT_TRUSTED)"
	WebTrust    = "CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR"

	EmailDistrust = "CKA_TRUST_EMAIL_PROTECTION CK_TRUST (CKT_NSS_MUST_VERIFY_TRUST|CKT_NSS_NOT_TRUSTED)"
	EmailTrust    = "CKA_TRUST_EMAIL_PROTECTION CK_TRUST CKT_NSS_TRUSTED_DELEGATOR"

	IssuerPrefix       = "CKA_ISSUER MULTILINE_OCTAL"        // Declaration of start of a CKA_ISSUER block
	SerialNumberPrefix = "CKA_SERIAL_NUMBER MULTILINE_OCTAL" // Declaration of start of a CKA_SERIAL_NUMBER block.
	PEMPrefix          = "CKA_VALUE MULTILINE_OCTAL"         // Declaration of start a CKA_VALUE (PEM) block.
)

var distrustWebRegex *regexp.Regexp
var distrustEmailRegex *regexp.Regexp

var countryName asn1.ObjectIdentifier
var organization asn1.ObjectIdentifier
var organizationalUnitName asn1.ObjectIdentifier
var commonName asn1.ObjectIdentifier
var stateOrProvinceName asn1.ObjectIdentifier
var localityName asn1.ObjectIdentifier
var email asn1.ObjectIdentifier
var serial asn1.ObjectIdentifier

func init() {
	distrustWebRegex = regexp.MustCompile(WebDistrust)
	distrustEmailRegex = regexp.MustCompile(EmailDistrust)

	countryName = asn1.ObjectIdentifier{2, 5, 4, 6}
	organization = asn1.ObjectIdentifier{2, 5, 4, 10}
	organizationalUnitName = asn1.ObjectIdentifier{2, 5, 4, 11}
	commonName = asn1.ObjectIdentifier{2, 5, 4, 3}
	stateOrProvinceName = asn1.ObjectIdentifier{2, 5, 4, 8}
	localityName = asn1.ObjectIdentifier{2, 5, 4, 7}
	email = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	serial = asn1.ObjectIdentifier{2, 5, 4, 5}
}

// ParseToNormalizedForm parses the provided certdata.txt into a normalized form
// that can be use to easily compare against a CCADB report.
func ParseToNormalizedForm(f io.Reader) ([]*utils.Entry, error) {
	b := bufio.NewReader(f)
	lineNum := 0
	r := make([]*utils.Entry, 0)
	for l, err := b.ReadString('\n'); err == nil; l, err = b.ReadString('\n') {
		lineNum++
		// A "distrust" object is a bare Trust object that is not preceeded by a Certificate object.
		if distrust := strings.HasPrefix(l, StartTrust); strings.HasPrefix(l, StartCertificate) || distrust {
			e, l, err := Extract(b, lineNum, distrust, "certdata")
			lineNum += l
			if err != nil {
				return r, err
			}
			r = append(r, e)
		}
	}
	return r, nil
}

// NewEntry constructs a new utils.Entry from the parsed ASN.1 issuer field, the serial number
// as a hex a string, the PEM as a base64 encoded string, the line number where entry started on,
// and the absolute path to the file where the entity was extracted from.
func NewEntry(i pkix.RDNSequence, s string, pem string, hash string, webTrust, emailTrust bool, ln int, fname string) *utils.Entry {
	var on string
	var oun string
	var cn string
	// A pkix.RDNSequence is just a type alias of a slice of OIDs, of which the
	// exact ordering is not guaranteed. As such, we just have to iterate over
	// the OIDs to figure out what they are.
	for _, attr := range i {
		oid := attr[0].Type
		switch value := attr[0].Value.(string); true {
		case oid.Equal(organization):
			on = value
		case oid.Equal(organizationalUnitName):
			oun = value
		case oid.Equal(commonName):
			cn = value
		}
	}
	return utils.NewEntry(on, oun, cn, s, pem, hash, webTrust, emailTrust, ln, fname)
}

// Extract extracts the entity from the bufio.Reader, 'b', that starts line number 'start'.
// 'distrust' is whether or not the entity is a distrust object. This is necessary since
// distrust objects do not have a PEM to parse out.
func Extract(b *bufio.Reader, start int, distrust bool, fname string) (*utils.Entry, int, error) {
	issuerFound := false
	serialFound := false
	pemFound := false
	webTrustFound := false
	emailTrustFound := false
	lineNum := 0
	var issuer pkix.RDNSequence
	var serialNum string
	var pem string
	var hash string
	var webTrust bool
	var emailTrust bool
	for l, err := b.ReadString('\n'); err == nil; l, err = b.ReadString('\n') {
		lineNum++
		// Putting this break guard here instead of the loop signature makes it easier to count lines.
		// Distrust objects lack a PEM. Hence (pemFound || distrust).
		if issuerFound && serialFound && webTrustFound && emailTrustFound && (pemFound || distrust) {
			break
		}
		switch true {
		case strings.HasPrefix(l, IssuerPrefix):
			oct, lcount := ExtractMultilineOctal(b)
			lineNum += lcount
			issuerFound = true
			if issuer, err = DecodeIssuer(oct); err != nil {
				return nil, lineNum, err
			}
		case strings.HasPrefix(l, SerialNumberPrefix):
			oct, lcount := ExtractMultilineOctal(b)
			lineNum += lcount
			serialFound = true
			if serialNum, err = DecodeSerialNumber(oct); err != nil {
				return nil, lineNum, err
			}
		case strings.HasPrefix(l, SerialNumberPrefix):
			oct, lcount := ExtractMultilineOctal(b)
			lineNum += lcount
			serialFound = true
			if serialNum, err = DecodeSerialNumber(oct); err != nil {
				return nil, lineNum, err
			}
		case !distrust && strings.HasPrefix(l, PEMPrefix):
			oct, lcount := ExtractMultilineOctal(b)
			lineNum += lcount
			pemFound = true
			if pem, hash, err = DecodeDER(oct); err != nil {
				return nil, lineNum, err
			}
		case strings.HasPrefix(l, WebTrust):
			webTrust = true
			webTrustFound = true
		case distrustWebRegex.MatchString(l):
			webTrust = false
			webTrustFound = true
		case strings.HasPrefix(l, EmailTrust):
			emailTrust = true
			emailTrustFound = true
		case distrustEmailRegex.MatchString(l):
			emailTrust = false
			emailTrustFound = true
		}
	}
	if !(issuerFound && serialFound && webTrustFound && emailTrustFound && (pemFound || distrust)) {
		return nil, lineNum, errors.New("unexpected EOF")
	}
	e := NewEntry(issuer, serialNum, pem, hash, webTrust, emailTrust, start, fname)
	return e, lineNum, nil
}

// DecodeIssuer parses the CKA_ISSUER MULTILINE_OCTAL field of certdata.txt.
func DecodeIssuer(octal string) (pkix.RDNSequence, error) {
	b, err := otobs(octal)
	if err != nil {
		return nil, err
	}
	var i pkix.RDNSequence
	if rest, err := asn1.Unmarshal(b, &i); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("issuer field had trailing data")
	}
	return i, nil
}

// DecodeSerialNumber takes a DER encoded octal string and returns
// the base64 encoded serial number.
func DecodeSerialNumber(octal string) (string, error) {
	b, err := otobs(octal)
	if err != nil {
		return "", err
	}
	s := new(big.Int)
	if rest, err := asn1.Unmarshal(b, &s); err != nil {
		return "", err
	} else if len(rest) != 0 {
		return "", errors.New("serial number field had trailing data")
	}
	// %x fmts to hex
	return fmt.Sprintf("%x", s), nil
}

// DecodeDER takes a DER encoded octal string and returns the base64
// encoded certificate as well as its SHA-256 hash. No newlines, BEGIN,
// or END fields are present on the decoded string.
func DecodeDER(octal string) (string, string, error) {
	b, err := otobs(octal)
	if err != nil {
		return "", "", err
	}
	c, err := x509.ParseCertificate(b)
	if err != nil {
		return "", "", err
	}
	h := sha256.New()
	h.Write(b)
	f := FmtFingerprint(fmt.Sprintf("%x", h.Sum(nil)))
	pem := base64.StdEncoding.EncodeToString(c.Raw)
	return pem, f, nil
}

// FmtFingerprint formats a SHA 256 hash with colons.
func FmtFingerprint(h string) string {
	h = strings.ToUpper(h)
	f := make([]byte, 95) // 64 characters + 31 ':'
	copy(f[0:2], h[0:2])
	ci := 2
	for i := 2; i < len(h); i += 2 {
		f[ci] = ':'
		copy(f[ci+1:ci+3], h[i:i+2])
		ci += 3
	}
	return string(f)
}

// ExtractMultilineOctal consumes the provided bufio.Reader and returns a string
// of '\' delimited octal values and then number of lines consumed to extract
// the octal value.
func ExtractMultilineOctal(b *bufio.Reader) (string, int) {
	var oct []string
	lines := 0
	for l, err := b.ReadString('\n'); err == nil; l, err = b.ReadString('\n') {
		lines++
		// Putting this break guard here instead of the loop signature makes it easier to count lines.
		if strings.HasPrefix(l, "END") {
			break
		}
		oct = append(oct, strings.Trim(l, "\n"))
	}
	return strings.Join(oct, ""), lines
}

// otobs converts a string containing `\` delimited octal values to a byte slice.
// An error can occur if a supposed octal value fails to convert to an integer.
func otobs(oct string) (result []byte, err error) {
	var b int64
	for _, o := range strings.Split(oct, `\`)[1:] {
		if b, err = strconv.ParseInt(o, 8, 0); err != nil {
			return
		}
		result = append(result, byte(b))
	}
	return
}
