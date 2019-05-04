/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package certutil

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
)

type Fingerprint = string

const (
	//-u certusage      Specify certificate usage:
	//C 	 SSL Client
	//V 	 SSL Server
	//I 	 IPsec
	//L 	 SSL CA
	//A 	 Any CA
	//Y 	 Verify CA
	//S 	 Email signer
	//R 	 Email Recipient
	//O 	 OCSP status responder
	//J 	 Object signer
	CertUsageSSLClient           = "C"
	CertUsageSSLServer           = "V"
	CertUsageIPsec               = "I"
	CertUsageSSLCA               = "L"
	CertUsageAnyCA               = "A"
	CertUsageVerifyCA            = "y"
	CertUsageEmailSigner         = "S"
	CertUsageEmailRecipient      = "R"
	CertUsageOCSPStatusResponder = "O"
	CertUsageObjectSigner        = "J"
)

const (
	NewCertificateDatabase = "-N"
	NoPassword             = "--empty-password"
	CertDbDirectory        = "-d"

	InstallCert     = "-A"
	CertName        = "-n"
	TrustArgs       = "-t"
	TrustedPeer     = "P,p,p"
	TrustedImplicit = ",,"
	TrustedCA       = "C"

	Verify          = "-V"
	VerifySignature = "-e"
	CertUsage       = "-u"
	SSLServer       = "V"

	ListChain = "-O"
)

const (
	VALID         = "certutil: certificate is valid"
	EXPIRED       = "certutil: certificate is invalid: Peer's Certificate has expired."
	ISSUER_UNKOWN = "certutil: certificate is invalid: Peer's Certificate issuer is not recognized."
)

const executable = "certutil"

type Certutil struct {
	tmpDir string
}

func NewCertutil() (Certutil, error) {
	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		return Certutil{}, err
	}
	return NewCerutilInto(tmpDir)
}

func NewCerutilInto(dir string) (certutil Certutil, err error) {
	certutil.tmpDir = dir
	out, err := execute([]string{NewCertificateDatabase, NoPassword, CertDbDirectory, certutil.tmpDir})
	if err != nil {
		log.Println(string(out))
	}
	return
}

func CertUtilFrom(dir string) (certutil Certutil) {
	certutil.tmpDir = dir
	return
}

//-t trustargs      Set the certificate trust attributes:
//trustargs is of the form x,y,z where x is for SSL, y is for S/MIME,
//and z is for code signing. Use ,, for no explicit trust.
//p 	 prohibited (explicitly distrusted)
//P 	 trusted peer
//c 	 valid CA
//T 	 trusted CA to issue client certs (implies c)
//C 	 trusted CA to issue server certs (implies c)
//u 	 user cert
//w 	 send warning
//g 	 make step-up cert
func (c Certutil) Install(cert *x509.Certificate) ([]byte, error) {
	var trustArgs string
	switch cert.Subject.CommonName == cert.Issuer.CommonName {
	case true:
		trustArgs = TrustedCA
	case false:
		trustArgs = TrustedImplicit
	}
	return execute([]string{
		InstallCert,
		TrustArgs, trustArgs,
		CertName, fingerprintOf(cert),
		CertDbDirectory, c.tmpDir,
	}, cert.Raw...)
}

//-u certusage      Specify certificate usage:
//C 	 SSL Client
//V 	 SSL Server
//I 	 IPsec
//L 	 SSL CA
//A 	 Any CA
//Y 	 Verify CA
//S 	 Email signer
//R 	 Email Recipient
//O 	 OCSP status responder
//J 	 Object signer
func (c Certutil) Verify(cert *x509.Certificate) ([]byte, error) {
	var certUsage string
	switch cert.IsCA {
	case true:
		certUsage = CertUsageSSLCA
	case false:
		certUsage = CertUsageSSLServer
	}
	return execute([]string{
		Verify,
		VerifySignature,
		CertName, fingerprintOf(cert),
		CertUsage, certUsage,
		CertDbDirectory, c.tmpDir,
	})
}

func (c Certutil) ListChain(cert *x509.Certificate) ([]Fingerprint, error) {
	out, err := execute([]string{
		ListChain,
		CertName, fingerprintOf(cert),
		CertDbDirectory, c.tmpDir,
	})
	if err != nil {
		return []Fingerprint{}, errors.Wrap(err, string(out))
	}
	var fingerprints []Fingerprint
	fmt.Print(string(out))
	for _, link := range bytes.Split(out, []byte{byte('\n')}) {
		fingerprints = append(fingerprints, string(bytes.TrimSpace(link)))
	}
	return fingerprints, nil
}

func (c Certutil) Delete() error {
	return os.RemoveAll(c.tmpDir)
}

func execute(args []string, input ...byte) ([]byte, error) {
	cmd := exec.Command(executable, args...)
	cmd.Stdin = bytes.NewBuffer(input)
	out, err := cmd.CombinedOutput()
	return bytes.TrimSpace(out), err
}

func fingerprintOf(cert *x509.Certificate) Fingerprint {
	hasher := crypto.SHA256.New()
	hasher.Write(cert.Raw)
	return fmt.Sprintf("%x", hasher.Sum(nil))
}
