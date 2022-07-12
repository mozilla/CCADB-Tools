/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package crl

import (
	"crypto/x509"
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"
)

type CRLStatus string

const (
	Good        CRLStatus = "good"
	Revoked               = "revoked"
	Unchecked             = "unchecked"
	BadResponse           = "badResponse"
)

type CRL struct {
	Error    string
	Endpoint string
	Status   CRLStatus
}

func VerifyChain(chain []*x509.Certificate) [][]CRL {
	crls := make([][]CRL, len(chain))
	if len(chain) == 1 {
		return crls
	}
	for i, cert := range chain[:len(chain)-1] {
		crls[i] = queryCRLs(cert)
	}
	crls[len(crls)-1] = make([]CRL, 0)
	return crls
}

func queryCRLs(certificate *x509.Certificate) []CRL {
	statuses := make([]CRL, len(certificate.CRLDistributionPoints))
	for i, url := range certificate.CRLDistributionPoints {
		statuses[i] = newCRL(certificate.SerialNumber, url)
	}
	if disagreement := allAgree(statuses); disagreement != nil {
		for _, status := range statuses {
			status.Error = disagreement.Error()
		}
	}
	return statuses
}

func allAgree(statuses []CRL) error {
	if len(statuses) <= 1 {
		return nil
	}
	checkedCRLs := make([]CRL, 0)
	for _, s := range statuses {
		if s.Status == Unchecked {
			continue
		}
		checkedCRLs = append(checkedCRLs, s)
	}
	firstAnswer := checkedCRLs[0]
	for _, otherAnswer := range checkedCRLs[1:] {
		if otherAnswer.Status != firstAnswer.Status {
			return errors.New("The listed CRLs disagree with each other")
		}
	}
	return nil
}

func newCRL(serialNumber *big.Int, distributionPoint string) (crl CRL) {
	crl.Endpoint = distributionPoint
	if strings.HasPrefix(distributionPoint, "ldap") {
		crl.Status = Unchecked
		return
	}
	req, err := http.NewRequest("GET", distributionPoint, nil)
	req.Header.Add("X-Automated-Tool", "https://github.com/mozilla/CCADB-Tools/capi CCADB test website verification tool")
	client := http.Client{}
	client.Timeout = time.Duration(20 * time.Second)
	raw, err := client.Do(req)
	if err != nil {
		crl.Error = errors.Wrapf(err, "failed to retrieve CRL from distribution point %v", distributionPoint).Error()
		crl.Status = BadResponse
		return
	}
	defer raw.Body.Close()
	if raw.StatusCode != http.StatusOK {
		crl.Error = errors.New(fmt.Sprintf("wanted 200 response, got %d", raw.StatusCode)).Error()
		crl.Status = BadResponse
		return
	}
	b, err := ioutil.ReadAll(raw.Body)
	if err != nil {
		crl.Error = errors.Wrapf(err, "failed to read response from CRL distribution point %v", distributionPoint).Error()
		crl.Status = BadResponse
		return
	}
	c, err := x509.ParseCRL(b)
	if err != nil {
		crl.Error = errors.Wrapf(err, "failed to parse provided CRL\n%v", raw).Error()
		crl.Status = BadResponse
		return
	}
	if c.TBSCertList.RevokedCertificates == nil {
		crl.Status = Good
		return
	}
	for _, revoked := range c.TBSCertList.RevokedCertificates {
		if revoked.SerialNumber.Cmp(serialNumber) == 0 {
			crl.Status = Revoked
			return
		}
	}
	crl.Status = Good
	return
}
