package ccadb

import (
	"encoding/csv"
	"net/http"
)

const report = "https://ccadb-public.secure.force.com/mozilla/PublicIntermediateCertsRevokedWithPEMCSV"

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
