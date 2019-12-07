package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"github.com/mozilla/CCADB-Tools/crlVerification/utils"
	"math/big"
	"testing"
)

const goodSingleCRL = `{
	"crl": "http://google.com/crl",
	"serial": "0123456789abcdef",
	"revocationDate": "2019/12/13",
	"revocationReason": "(10) aACompromise"
}`

func TestInput_UnmarshalJSON_Single(t *testing.T) {
	i := NewInput()
	if err := json.Unmarshal([]byte(goodSingleCRL), &i); err != nil {
		t.Fatal(err)
	}
	if len(i.errs) != 0 {
		t.Fatal(i.errs)
	}
	if len(i.Crl) != 1 {
		t.Fatalf("wanted 1 crl, got %d", len(i.Crl))
	}
}

const good = `{
	"crl": ["http://google.com/crl", "http://google.com/crl"],
	"serial": "0123456789abcdef",
	"revocationDate": "2019/12/13",
	"revocationReason": "(10) aACompromise"
}`

func TestInput_UnmarshalJSON(t *testing.T) {
	i := NewInput()
	if err := json.Unmarshal([]byte(good), &i); err != nil {
		t.Fatal(err)
	}
	if len(i.errs) != 0 {
		t.Fatal(i.errs)
	}
	if len(i.Crl) != 2 {
		t.Fatalf("wanted 2 crls, got %d", len(i.Crl))
	}
}

const missingCRL = `{
	"serial": "0123456789abcdef",
	"revocationDate": "2019/12/13",
	"revocationReason": "(10) aACompromise"
}`

func TestInput_UnmarshalJSON_MissingCRL(t *testing.T) {
	i := NewInput()
	if err := json.Unmarshal([]byte(missingCRL), &i); err != nil {
		t.Fatal(err)
	}
	if len(i.errs) != 0 {
		t.Fatal(i.errs)
	}
	if len(i.Crl) != 0 {
		t.Fatalf("wanted 0 CRLs, got %d", len(i.Crl))
	}
}

const missingSerial = `{
	"crl": "http://google.com/crl",
	"revocationDate": "2019/12/13",
	"revocationReason": "(10) aACompromise"
}`

func TestInput_UnmarshalJSON_MissingSerial(t *testing.T) {
	i := NewInput()
	if err := json.Unmarshal([]byte(missingSerial), &i); err != nil {
		t.Fatal(err)
	}
	if len(i.errs) != 1 {
		t.Fatal(i.errs)
	}
	if i.errs[0].Error() != `"serial" is a required field` {
		t.Fatal(i.errs)
	}
}

const missingRevocationDate = `{
	"crl": "http://google.com/crl",
	"serial": "0123456789abcdef",
	"revocationReason": "(10) aACompromise"
}`

func TestInput_UnmarshalJSON_MissingRevocationDate(t *testing.T) {
	i := NewInput()
	if err := json.Unmarshal([]byte(missingRevocationDate), &i); err != nil {
		t.Fatal(err)
	}
	if len(i.errs) != 1 {
		t.Fatal(i.errs)
	}
	if i.errs[0].Error() != `"revocationDate" is a required field` {
		t.Fatal(i.errs)
	}
}

const nilRevocationReason = `{
	"crl": "http://google.com/crl",
	"serial": "0123456789abcdef",
	"revocationDate": "2019/12/13"
}`

func TestInput_UnmarshalJSON_NilRevocationReason(t *testing.T) {
	i := NewInput()
	if err := json.Unmarshal([]byte(nilRevocationReason), &i); err != nil {
		t.Fatal(err)
	}
	if len(i.errs) != 0 {
		t.Fatal(i.errs)
	}
	if i.Reason != utils.NOT_GIVEN {
		t.Fatalf("wanted %s got %s", utils.NOT_GIVEN, i.Reason)
	}
}

const RFC_5280_EXAMPLE_CRL = `MIIBYDCBygIBATANBgkqhkiG9w0BAQUFADBDMRMwEQYKCZImiZPyLGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTETMBEGA1UEAxMKRXhhbXBsZSBDQRcNMDUwMjA1MTIwMDAwWhcNMDUwMjA2MTIwMDAwWjAiMCACARIXDTA0MTExOTE1NTcwM1owDDAKBgNVHRUEAwoBAaAvMC0wHwYDVR0jBBgwFoAUCGivhTPIOUp6+IKTjnBqSiCELDIwCgYDVR0UBAMCAQwwDQYJKoZIhvcNAQEFBQADgYEAItwYffcIzsx10NBqm60Q9HYjtIFutW2+DvsVFGzIF20f7pAXom9g5L2qjFXejoRvkvifEBInr0rUL4XiNkR9qqNMJTgV/wD9Pn7uPSYS69jnK2LiK8NGgO94gtEVxtCccmrLznrtZ5mLbnCBfUNCdMGmr8FVF6IzTNYGmCuk/C4=`

var exampleSerial = big.NewInt(18)
var exampleDate, _ = utils.TimeFromString("2004/11/19")
var exampleReason = utils.KEY_COMPROMISE

const example = `{
	"crl": "http://google.com/crl",
	"serial": "000000000012",
	"revocationDate": "2004/11/19",
	"revocationReason": "(1) keyCompromise"
}`

func TestCRLPass(t *testing.T) {
	b, err := base64.StdEncoding.DecodeString(RFC_5280_EXAMPLE_CRL)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseCRL(b)
	if err != nil {
		panic(err)
	}
	i := NewInput()
	err = json.Unmarshal([]byte(example), &i)
	if err != nil {
		t.Fatal(err)
	}
	ret := validate(i, crl)
	if len(ret.Errors) != 0 {
		t.Fatal(ret.Errors)
	}
	if ret.Result != PASS {
		t.Fatal("expected PASS got FAIL")
	}
}

const exampleWrongSerial = `{
	"crl": "http://google.com/crl",
	"serial": "000000000011",
	"revocationDate": "2004/11/19",
	"revocationReason": "(1) keyCompromise"
}`

func TestCRLSerialNotFound(t *testing.T) {
	b, err := base64.StdEncoding.DecodeString(RFC_5280_EXAMPLE_CRL)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseCRL(b)
	if err != nil {
		panic(err)
	}
	i := NewInput()
	err = json.Unmarshal([]byte(exampleWrongSerial), &i)
	if err != nil {
		t.Fatal(err)
	}
	ret := validate(i, crl)
	if len(ret.Errors) != 1 {
		t.Fatal(ret.Errors)
	}
	if ret.Errors[0].Error() != `"11" was not found in the given CRL` {
		t.Fatalf(`wanted ""11" was not found in the given CRL", got "%s"`, ret.Errors[0])
	}
	if ret.Result != FAIL {
		t.Fatal("expected FAIL got PASS")
	}
}

const exampleWrongDate = `{
	"crl": "http://google.com/crl",
	"serial": "000000000012",
	"revocationDate": "2004/11/20",
	"revocationReason": "(1) keyCompromise"
}`

func TestCRLWrongDate(t *testing.T) {
	b, err := base64.StdEncoding.DecodeString(RFC_5280_EXAMPLE_CRL)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseCRL(b)
	if err != nil {
		panic(err)
	}
	i := NewInput()
	err = json.Unmarshal([]byte(exampleWrongDate), &i)
	if err != nil {
		t.Fatal(err)
	}
	ret := validate(i, crl)
	if len(ret.Errors) != 1 {
		t.Fatal(ret.Errors)
	}
	if ret.Errors[0].Error() != `Revocation dates did not match. We wanted 2004/11/20, but got 2004/11/19` {
		t.Fatalf(`wanted "Revocation dates did not match. We wanted 2004/11/20, but got 2004/11/19", got "%s"`, ret.Errors[0])
	}
	if ret.Result != FAIL {
		t.Fatal("expected FAIL got PASS")
	}
}

const exampleWrongReason = `{
	"crl": "http://google.com/crl",
	"serial": "000000000012",
	"revocationDate": "2004/11/19",
	"revocationReason": "(0) unspecified"
}`

func TestCRLWrongReason(t *testing.T) {
	b, err := base64.StdEncoding.DecodeString(RFC_5280_EXAMPLE_CRL)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseCRL(b)
	if err != nil {
		panic(err)
	}
	i := NewInput()
	err = json.Unmarshal([]byte(exampleWrongReason), &i)
	if err != nil {
		t.Fatal(err)
	}
	ret := validate(i, crl)
	if len(ret.Errors) != 1 {
		t.Fatal(ret.Errors)
	}
	if ret.Errors[0].Error() != `Revocation reasons did not match. We wanted (0) unspecified, but got (1) keyCompromise` {
		t.Fatalf(`wanted "Revocation reasons did not match. We wanted (0) unspecified, but got (1) keyCompromise", got "%s"`, ret.Errors[0])
	}
	if ret.Result != FAIL {
		t.Fatal("expected FAIL got PASS")
	}
}

const exampleWrongReasonAndDate = `{
	"crl": "http://google.com/crl",
	"serial": "000000000012",
	"revocationDate": "2004/11/20",
	"revocationReason": "(0) unspecified"
}`

func TestCRLWrongReasonAndDate(t *testing.T) {
	b, err := base64.StdEncoding.DecodeString(RFC_5280_EXAMPLE_CRL)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseCRL(b)
	if err != nil {
		panic(err)
	}
	i := NewInput()
	err = json.Unmarshal([]byte(exampleWrongReasonAndDate), &i)
	if err != nil {
		t.Fatal(err)
	}
	ret := validate(i, crl)
	if len(ret.Errors) != 2 {
		t.Fatal(ret.Errors)
	}
	if ret.Errors[0].Error() != `Revocation dates did not match. We wanted 2004/11/20, but got 2004/11/19` {
		t.Fatalf(`wanted "Revocation dates did not match. We wanted 2004/11/20, but got 2004/11/19", got "%s"`, ret.Errors[0])
	}
	if ret.Errors[1].Error() != `Revocation reasons did not match. We wanted (0) unspecified, but got (1) keyCompromise` {
		t.Fatalf(`wanted "Revocation reasons did not match. We wanted (0) unspecified, but got (1) keyCompromise", got "%s"`, ret.Errors[1])
	}
	if ret.Result != FAIL {
		t.Fatal("expected FAIL got PASS")
	}
}
