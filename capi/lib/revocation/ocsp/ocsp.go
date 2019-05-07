/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package ocsp

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	ocsplib "golang.org/x/crypto/ocsp"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// RFC 6960
//
// Appendix A. OCSP over HTTP
//
// A.1.  Request
//
// HTTP-based OCSP requests can use either the GET or the POST method to
// submit their requests.  To enable HTTP caching, small requests (that
// after encoding are less than 255 bytes) MAY be submitted using GET.
// If HTTP caching is not important or if the request is greater than
// 255 bytes, the request SHOULD be submitted using POST.  Where privacy
// is a requirement, OCSP transactions exchanged using HTTP MAY be
// protected using either Transport Layer Security/Secure Socket Layer
// (TLS/SSL) or some other lower-layer protocol.
//
// An OCSP request using the GET method is constructed as follows:
//
// GET {url}/{url-encoding of base-64 encoding of the DER encoding of
// the OCSPRequest}
//
// where {url} may be derived from the value of the authority
// information access extension in the certificate being checked for
// revocation, or other local configuration of the OCSP client.
//
// An OCSP request using the POST method is constructed as follows: The
// Content-Type header has the value "application/ocsp-request", while
// the body of the message is the binary value of the DER encoding of
// the OCSPRequest.

// 4.2.1.  ASN.1 Specification of the OCSP Response
//
//
// CertStatus ::= CHOICE {
//	good        [0]     IMPLICIT NULL,
//	expired     [1]     IMPLICIT RevokedInfo,
//	unknown     [2]     IMPLICIT UnknownInfo }

type OCSPStatus int

const (
	Good = iota
	Revoked
	Unknown
	Unauthorized

	CryptoVerifcationError
	BadResponse

	InternalError
)

type OCSP struct {
	Error     string
	Responder string
	Status    OCSPStatus
}

func (o OCSP) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"Responder": o.Responder,
		"Status":    o.Status.String(),
		"Error":     o.Error,
	})
}

func (o *OCSP) UnmarshalJSON(data []byte) error {
	r := make(map[string]string)
	err := json.Unmarshal(data, &r)
	if err != nil {
		return err
	}
	responder, ok := r["Responder"]
	if !ok {
		return errors.New("Invalid OCSP struct, missing Responder key")
	}
	o.Responder = responder
	s, ok := r["Status"]
	if !ok {
		return errors.New("Invalid OCSP struct, missing Status key")
	}
	status, err := FromString(s)
	if err != nil {
		return err
	}
	o.Status = status
	e, ok := r["Error"]
	if !ok {
		return errors.New("Invalid OCSP struct, missing Error key")
	}
	o.Error = e
	return nil
}

func FromString(data string) (OCSPStatus, error) {
	switch data {
	case `good`:
		return Good, nil
	case `revoked`:
		return Revoked, nil
	case `unknown`:
		return Unknown, nil
	case `unauthorized`:
		return Unauthorized, nil
	case `badResponse`:
		return BadResponse, nil
	case `internalError`:
		return InternalError, nil
	default:
		return Unknown, errors.New("unknown OCSPStatus type " + string(data))
	}
}

func (o OCSPStatus) String() string {
	switch o {
	case Good:
		return `good`
	case Revoked:
		return `revoked`
	case Unknown:
		return `unknown`
	case Unauthorized:
		return `unauthorized`
	case BadResponse:
		return `badResponse`
	case CryptoVerifcationError:
		return `cryptoVerificationError`
	case InternalError:
		return `internalError`
	default:
		return `error_unknown_ocsp_status`
	}
}

const OCSPContentType = "application/ocsp-request"

func VerifyChain(chain []*x509.Certificate) [][]OCSP {
	ocsps := make([][]OCSP, len(chain))
	if len(chain) == 1 {
		return ocsps
	}
	for i, cert := range chain[:len(chain)-1] {
		ocsps[i] = queryOCSP(cert, chain[i+1])
	}
	ocsps[len(ocsps)-1] = make([]OCSP, 0)
	return ocsps
}

func queryOCSP(certificate, issuer *x509.Certificate) []OCSP {
	responses := make([]OCSP, len(certificate.OCSPServer))
	for i, responder := range certificate.OCSPServer {
		responses[i] = newOCSPResponse(certificate, issuer, responder)
	}
	return responses
}

func newOCSPResponse(certificate, issuer *x509.Certificate, responder string) (response OCSP) {
	response.Responder = responder
	req, err := ocsplib.CreateRequest(certificate, issuer, nil)
	if err != nil {
		response.Status = InternalError
		response.Error = errors.Wrap(err, "failed to create DER encoded OCSP request").Error()
		return
	}
	r, err := http.NewRequest("POST", responder, bytes.NewReader(req))
	if err != nil {
		response.Status = InternalError
		response.Error = errors.Wrap(err, "failed to create HTTP POST for OCSP request").Error()
		return
	}
	r.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:64.0) Gecko/20100101 Firefox/64.0")
	r.Header.Set("Content-Type", OCSPContentType)
	client := http.Client{}
	client.Timeout = time.Duration(10 * time.Second)
	ret, err := client.Do(r)
	if err != nil {
		response.Status = BadResponse
		response.Error = errors.Wrapf(err, "failed to retrieve HTTP POST response from %v", responder).Error()
		return
	}
	defer ret.Body.Close()
	httpResp, err := ioutil.ReadAll(ret.Body)
	if err != nil {
		response.Status = BadResponse
		response.Error = err.Error()
		return
	}
	serverResponse, err := ocsplib.ParseResponse(httpResp, issuer)
	if err != nil {
		switch true {
		case strings.Contains(err.Error(), `unauthorized`):
			response.Status = Unauthorized
		case strings.Contains(err.Error(), `verification error`):
			response.Error = err.Error()
			response.Status = CryptoVerifcationError
		case itLooksLikeHTML(httpResp):
			response.Status = BadResponse
			response.Error = fmt.Sprintf("Response appears to be HTML. Error: %s", err.Error())
		default:
			response.Status = BadResponse
			response.Error = err.Error()
		}
		return
	}
	switch serverResponse.Status {
	case ocsplib.Revoked:
		response.Status = Revoked
	case ocsplib.Good:
		response.Status = Good
	case ocsplib.Unknown:
		response.Status = Unknown
	}
	return
}

var HTMLish = regexp.MustCompile(`(<html>|<body>)`)

func itLooksLikeHTML(response []byte) bool {
	return HTMLish.Match(response)
}
