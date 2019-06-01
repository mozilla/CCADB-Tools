package ccadb

import (
	"encoding/csv"
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

func (e *Entry) Key() string {
	return fmt.Sprintf("%s%s%s", e.DecodeSerial(), e.IssuerCommonName, e.IssuerOrganizationName)
}

func (e *Entry) DecodeSerial() string {
	s, err := hex.DecodeString(e.Serial)
	if err != nil {
		panic(err)
	}
	return big.NewInt(0).SetBytes(s).String()
}

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

//func Retrieve() []*Entry {
//	resp, err := http.DefaultClient.Get(report)
//	if err != nil {
//		panic(err)
//	}
//	defer resp.Body.Close()
//	var e []*Entry
//	if err := gocsv.Unmarshal(resp.Body, &e); err != nil {
//		panic(err)
//	}
//	return e
//}

var schema = map[string]int{"CA Owner": 0,
	"Revocation Status":                1,
	"RFC 5280 Revocation Reason Code":  2,
	"Date of Revocation":               3,
	"OneCRL Status":                    4,
	"Certificate Serial Number":        5,
	"CA Owner/Certificate Name":        6,
	"Certificate Issuer Common Name":   7,
	"Certificate Issuer Organization":  8,
	"Certificate Subject Common Name":  9,
	"Certificate Subject Organization": 10,
	"SHA-256 Fingerprint":              11,
	"Subject + SPKI SHA256":            12,
	"Valid From [GMT]":                 13,
	"Valid To [GMT]":                   14,
	"Public Key Algorithm":             15,
	"Signature Hash Algorithm":         16,
	"CRL URL(s)":                       17,
	"Alternate CRL":                    18,
	"OCSP URL(s)":                      19,
	"Comments":                         20,
	"PEM Info":                         21}

func retrieve() [][]string {
	resp, err := http.DefaultClient.Get(report)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	r := csv.NewReader(resp.Body)
	rows, err := r.ReadAll()
	if err != nil {
		panic(err)
	}
	return rows[1:]
}
