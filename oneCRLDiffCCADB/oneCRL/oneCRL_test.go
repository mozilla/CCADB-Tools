package oneCRL

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
)

func TestGet(t *testing.T) {
	fmt.Println(tostring())
}

func TestSerde(t *testing.T) {
	fmt.Println(Retrieve())
}

const one = `{"schema":1557911212456,"details":{"bug":"","who":"","why":"","name":"","created":""},"enabled":true,"issuerName":"MEoxCzAJBgNVBAYTAkNIMRAwDgYDVQQKEwdXSVNlS2V5MSkwJwYDVQQDEyBXSVNlS2V5IENlcnRpZnlJRCBQb2xpY3kgR0IgQ0EgMQ==","serialNumber":"CYut7lnH+rk=","id":"badf76bb-8e38-4908-905c-7cc1e4183814","last_modified":1557423813772}`

func TestDe(t *testing.T) {
	var lol OneCRLIntermediate
	err := json.Unmarshal([]byte(one), &lol)
	if err != nil {
		panic(err)
	}
	fmt.Println(lol.IssuerName)
}

func TestSerial(t *testing.T) {
	serial := "CYut7lnH+rk="
	a, err := base64.StdEncoding.DecodeString(serial)
	if err != nil {
		panic(err)
	}
	fmt.Println(a)

	b, err := hex.DecodeString("6B0549F708B200BE")
	if err != nil {
		panic(err)
	}
	fmt.Println(b)
}
