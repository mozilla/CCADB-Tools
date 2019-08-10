/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package oneCRL

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
)

const OneCRLEndpoint = "https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/certificates/records"

type OneCRLIntermediates struct {
	Data []*OneCRLIntermediate `json:"data"`
}

type OneCRLIntermediate struct {
	Schema  int `json:"schema"`
	Details struct {
		Bug     string `json:"bug"`
		Who     string `json:"who"`
		Why     string `json:"why"`
		Name    string `json:"name"`
		Created string `json:"created"`
	} `json:"details"`
	Enabled      bool   `json:"enabled"`
	IssuerName   Name   `json:"issuerName"`
	SerialNumber string `json:"serialNumber"`
	Id           string `json:"id"`
	LastModified int    `json:"last_modified"`
}

// Key constructs a string that is the concatenation of the certificate serial (decoded from base64 to an decimal value)
// the issuer common name, and the issuer organization name. This key is used to join the results of OneCRL with the
// CCADB.
func (o *OneCRLIntermediate) Key() string {
	cn, org := o.IssuerName.Key()
	return fmt.Sprintf("%s%s%s", o.decodeSerial(), cn, org)
}

// Retrieve downloads the OneCRL report located at
// https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/certificates/records
// and returns a mapping "key"s to entries.
//
// The "key" in this case is the string concatenation of the decimal value of the certificate serial number,
// the issuer common name, and the issuer organization name.
func Retrieve() (map[string]*OneCRLIntermediate, error) {
	result := make(map[string]*OneCRLIntermediate)
	var intermediates OneCRLIntermediates
	resp, err := http.DefaultClient.Get(OneCRLEndpoint)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&intermediates)
	if err != nil {
		return result, err
	}
	for _, cert := range intermediates.Data {
		result[cert.Key()] = cert
	}
	return result, nil
}

func (o *OneCRLIntermediate) decodeSerial() string {
	s, err := base64.StdEncoding.DecodeString(o.SerialNumber)
	if err != nil {
		panic(err)
	}
	return big.NewInt(0).SetBytes(s).String()
}

// Name wraps a a vanilla RDN so that we can attach further methods for deserialization from JSON and extraction
// of the issuer Common Name and Organization Name.
type Name struct {
	// https://tools.ietf.org/html/rfc5280#section-4.1.2.4
	pkix.RDNSequence
}

func (n *Name) Key() (string, string) {
	cn := ""
	on := ""
	for _, i := range n.RDNSequence {
		for _, j := range i {
			switch j.Type.String() {
			// CN http://oidref.com/2.5.4.3
			case "2.5.4.3":
				cn = fmt.Sprint(j.Value)
			// ON http://oidref.com/2.5.4.10
			case "2.5.4.10":
				on = fmt.Sprint(j.Value)
			}
		}
	}
	return cn, on
}

func (n *Name) UnmarshalJSON(raw []byte) error {
	// As it comes in, this buffer is just a JSON string, which
	// includes double quotes that we do not want or need.
	raw = bytes.Trim(raw, `"`)
	dst := make([]byte, len(raw))
	_, err := base64.StdEncoding.Decode(dst, raw)
	if err != nil {
		return err
	}
	_, err = asn1.Unmarshal(dst, &n.RDNSequence)
	if err != nil {
		return err
	}
	return nil
}
