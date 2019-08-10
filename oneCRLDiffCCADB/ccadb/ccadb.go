/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package ccadb

import (
	"encoding/hex"
	"fmt"
	"github.com/gocarina/gocsv"
	"math/big"
	"net/http"
)

const report = "https://ccadb-public.secure.force.com/mozilla/PublicIntermediateCertsRevokedWithPEMCSV"

const (
	Added      = "Added to OneCRL"
	ReadyToAdd = "Ready to Add"
	Expired    = "Cert Expired"
)

type Entry struct {
	Serial                 string `csv:"Certificate Serial Number" json:"serial"`
	RevocationStatus       string `csv:"OneCRL Status" json:"revocationStatus"`
	IssuerCommonName       string `csv:"Certificate Issuer Common Name" json:"issuerCN"`
	IssuerOrganizationName string `csv:"Certificate Issuer Organization" json:"issuerON"`
	Fingerprint            string `csv:"SHA-256 Fingerprint" json:"fingerprint"`
}

// Key constructs a string that is the concatenation of the certificate serial (decoded from hex to an decimal value)
// the issuer common name, and the issuer organization name. This key is used to join the results of the CCADB
// with OneCRL.
func (e *Entry) Key() string {
	return fmt.Sprintf("%s%s%s", e.decodeSerial(), e.IssuerCommonName, e.IssuerOrganizationName)
}

// Retrieve downloads the CCADB report located at
// https://ccadb-public.secure.force.com/mozilla/PublicIntermediateCertsRevokedWithPEMCSV
// and returns a mapping "key"s to entries.
//
// The "key" in this case is the string concatenation of the decimal value of the certificate serial number,
// the issuer common name, and the issuer organization name.
func Retrieve() (map[string]*Entry, error) {
	result := make(map[string]*Entry, 0)
	resp, err := http.DefaultClient.Get(report)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()
	var e []*Entry
	if err := gocsv.Unmarshal(resp.Body, &e); err != nil {
		return result, err
	}
	for _, cert := range e {
		result[cert.Key()] = cert
	}
	return result, err
}

func (e *Entry) decodeSerial() string {
	s, err := hex.DecodeString(e.Serial)
	if err != nil {
		panic(err)
	}
	return big.NewInt(0).SetBytes(s).String()
}
