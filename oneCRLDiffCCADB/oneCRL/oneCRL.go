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

var (
	oidCountry            = []int{2, 5, 4, 6}
	oidOrganization       = []int{2, 5, 4, 10}
	oidOrganizationalUnit = []int{2, 5, 4, 11}
	oidCommonName         = []int{2, 5, 4, 3}
	oidSerialNumber       = []int{2, 5, 4, 5}
	oidLocality           = []int{2, 5, 4, 7}
	oidProvince           = []int{2, 5, 4, 8}
	oidStreetAddress      = []int{2, 5, 4, 9}
	oidPostalCode         = []int{2, 5, 4, 17}
)

var attributeTypeNames = map[string]string{
	"2.5.4.6":  "C",
	"2.5.4.10": "O",
	"2.5.4.11": "OU",
	"2.5.4.3":  "CN",
	"2.5.4.5":  "SERIALNUMBER",
	"2.5.4.7":  "L",
	"2.5.4.8":  "ST",
	"2.5.4.9":  "STREET",
	"2.5.4.17": "POSTALCODE",
}

type Name struct {
	// https://tools.ietf.org/html/rfc5280#section-4.1.2.4
	pkix.RDNSequence
}

func (n *Name) Key() (string, string) {
	cn := ""
	o := ""
	for _, i := range n.RDNSequence {
		for _, j := range i {
			switch j.Type.String() {
			case "2.5.4.3":
				//fmt.Println("asdasd", j.Value)
				cn = fmt.Sprint(j.Value)
			case "2.5.4.10":
				o = fmt.Sprint(j.Value)
			}
		}
	}
	return cn, o
}

func (n *Name) UnmarshalJSON(raw []byte) error {
	raw = bytes.Trim(raw, `"`)
	dst := bytes.Trim(raw, `"`)
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

func (o *OneCRLIntermediate) Key() string {
	cn, org := o.IssuerName.Key()
	return fmt.Sprintf("%s%s%s", o.DecodeSerial(), cn, org)
}

func (o *OneCRLIntermediate) DecodeSerial() string {
	s, err := base64.StdEncoding.DecodeString(o.SerialNumber)
	if err != nil {
		panic(err)
	}
	return big.NewInt(0).SetBytes(s).String()
}

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

//func Retrieve() (OneCRLIntermediates, error) {
//	var intermediates OneCRLIntermediates
//	resp, err := http.DefaultClient.Get(OneCRLEndpoint)
//	if err != nil {
//		return intermediates, err
//	}
//	defer resp.Body.Close()
//	err = json.NewDecoder(resp.Body).Decode(&intermediates)
//	return intermediates, err
//}
