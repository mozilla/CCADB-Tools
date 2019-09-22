/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package utils

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

type CRLNotGiven struct{}

func (c CRLNotGiven) Error() string {
	return "No CRL URL was provided"
}

type CRLDownloadFailed struct {
	url string
	err error
}

func (c CRLDownloadFailed) Error() string {
	// @TODO test this fmting
	return fmt.Sprintf("%s failed to download. error: %v", c.url, c.err)
}

type CRLFailedToParse struct {
	url string
	err error
}

func (c CRLFailedToParse) Error() string {
	// @TODO test this fmting
	return fmt.Sprintf("%s failed to parse. error: %v", c.url, c.err)
}

func CRLFromURL(crlUrl *string) (*pkix.CertificateList, error) {
	if crlUrl == nil {
		return nil, CRLNotGiven{}
	}
	resp, err := http.Get(*crlUrl)
	if err != nil {
		return nil, CRLDownloadFailed{*crlUrl, err}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, CRLDownloadFailed{*crlUrl, errors.New(fmt.Sprintf("recieved  status code %v", resp.StatusCode))}
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("%v\n", err)
		}
	}()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, CRLDownloadFailed{*crlUrl, err}
	}
	crl, err := x509.ParseCRL(body)
	if err != nil {
		return nil, CRLFailedToParse{*crlUrl, err}
	}
	return crl, nil
}
