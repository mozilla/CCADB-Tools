/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package crtSh

import (
	"bufio"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const a = "TXxtAQ=="
const b = "SUEs5ABThOepKci5Vzg="

//SELECT c.CERTIFICATE
//        certificate c
//        x509_serialNumber(c.CERTIFICATE) = decode($1, 'hex')
//    GROUP BY c.ID, c.ISSUER_CA_ID, ISSUER_NAME, NAME_VALUE
//    ORDER BY MIN_ENTRY_TIMESTAMP DESC, NAME_VALUE, ISSUER_NAME

func TestWhy(t *testing.T) {
	us := toSet(getUnknownUs())
	them := toSet(getUnknownThem())
	inUsNotThem := diff(us, them)
	inThemNotUs := diff(them, us)
	t.Log(len(us))
	t.Log(len(them))
	t.Log(inUsNotThem)
	t.Log(len(inUsNotThem))
	t.Log(inThemNotUs)
	t.Log(len(inThemNotUs))
}

func diff(a, b map[string]bool) []string {
	r := make([]string, 0)
	for k, _ := range a {
		if ok := b[k]; !ok {
			r = append(r, k)
		}
	}
	return r
}

func toSet(list []string) map[string]bool {
	m := make(map[string]bool)
	for _, l := range list {
		m[l] = true
	}
	return m
}

const certs = `H:\TestRepo\certs`

func getUnknownUs() []string {
	dirs, err := ioutil.ReadDir(certs)
	if err != nil {
		panic(err)
	}
	unknown := make([]string, 0)
	for _, d := range dirs {
		if strings.HasPrefix(d.Name(), "Serial_") {
			unknown = append(unknown, strings.TrimPrefix(d.Name(), "Serial_"))
		}
	}
	return unknown
}

const crtsh = `H:\OneCRL-Viewer\onecrl.html`

func getUnknownThem() []string {
	b, err := ioutil.ReadFile(crtsh)
	if err != nil {
		panic(err)
	}
	s := string(b)
	r := bufio.NewReader(strings.NewReader(s))
	unknown := make([]string, 0)
	known := make([]string, 0)
	for line, err := r.ReadString('\n'); err == nil; line, err = r.ReadString('\n') {
		if strings.TrimSpace(line) != "<TR>" {
			continue
		}
		line, err = r.ReadString('\n')
		if err != nil {
			continue
		}
		has := false
		if strings.TrimSpace(line) != "<TD>&nbsp;</TD>" {
			has = true
		}
		for i := 0; i < 4; i++ {
			_, err = r.ReadString('\n')
			if err != nil {
				continue
			}
		}
		line, err = r.ReadString('\n')
		if err != nil {
			continue
		}
		serial := strings.ToUpper(regexp.MustCompile(`(<T(D|H)>|</T(D|H)>)`).ReplaceAllString(strings.TrimSpace(line), ""))
		//serial := strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(line), "<TD>", ""), "</TD>", "")
		if !has {
			unknown = append(unknown, serial)
		} else {
			known = append(known, serial)
		}
	}
	return unknown
}

func TestGetCert(t *testing.T) {
	db, err := sql.Open("postgres", connectionString)
	rows, err := db.Query(`SELECT c.CERTIFICATE FROM
        certificate c WHERE
        x509_serialNumber(c.CERTIFICATE) in (decode($1, 'hex'), decode($2, 'hex'))`, "0A", "BB")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var cert []byte
		rows.Scan(&cert)
		c, err := x509.ParseCertificate(cert)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(fmt.Sprintf("%s", c.Issuer.ToRDNSequence()))
	}
}

func TestSingle(t *testing.T) {
	certs := get("022EDC04962A044D08F4D772A197D1AF")
	is, i := deserIssuer("MIG9MQswCQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAyMDA4IFZlcmlTaWduLCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxODA2BgNVBAMTL1ZlcmlTaWduIFVuaXZlcnNhbCBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5")
	for _, r := range i {
		t.Log(r)
	}
	t.Log(is)
	for _, c := range certs {
		t.Log(c.Issuer.ToRDNSequence().String())
		for _, r := range c.Issuer.ToRDNSequence() {
			t.Log(r)
		}
	}
}

func deserIssuer(issuer string) (string, pkix.RDNSequence) {
	i, err := base64.StdEncoding.DecodeString(issuer)
	if err != nil {
		panic(err)
	}
	var name pkix.RDNSequence
	_, err = asn1.Unmarshal(i, &name)
	if err != nil {
		panic(err)
	}
	return name.String(), name
}

func get(serial string) []*x509.Certificate {
	db, err := sql.Open("postgres", connectionString)
	rows, err := db.Query(`SELECT c.CERTIFICATE FROM
        certificate c WHERE
        x509_serialNumber(c.CERTIFICATE) = (decode($1, 'hex'))`, serial)
	if err != nil {
		panic(err)
	}
	certs := make([]*x509.Certificate, 0)
	for rows.Next() {
		var cert []byte
		rows.Scan(&cert)
		c, err := x509.ParseCertificate(cert)
		if err != nil {
			panic(err)
		}
		certs = append(certs, c)
	}
	return certs
}

//
//func TestTTT(t *testing.T) {
//	Init()
//	resp, err := http.DefaultClient.Get(kinto.kintoURL)
//	if err != nil {
//		t.Fatal(err)
//	}
//	defer resp.Body.Close()
//	var k kinto.KintoArray
//	err = json.NewDecoder(resp.Body).Decode(&k)
//	if err != nil {
//		t.Fatal(err)
//	}
//	changes := make(kinto.ChangeSet, len(k.Data))
//	for _, k := range k.Data {
//		changes[k] = kinto.Added
//	}
//	certs, err := GetCerts(changes)
//	if err != nil {
//		t.Fatal(err)
//	}
//	t.Log(certs)
//	for change := range changes {
//		t.Log(change.Key())
//	}
//	//for e := range changes {
//	//	_, ok := certs[e.Key()]
//	//	if !ok {
//	//		t.Log("boo")
//	//	} else {
//	//		t.Log(certs[e.Key()])
//	//		//t.Log("yayab")
//	//	}
//	//}
//	//q, args := BuildQuery(k.Data)
//	//t.Log(q)
//	//rows, err := db.Query(q, args...)
//	//if err != nil {
//	//	t.Fatal(err)
//	//}
//	//for rows.Next() {
//	//	var cert []byte
//	//	rows.Scan(&cert)
//	//	c, err := x509.ParseCertificate(cert)
//	//	if err != nil {
//	//		t.Log(err)
//	//		continue
//	//	}
//	//	t.Log(fmt.Sprintf("%X", c.SerialNumber))
//	//}
//}

const cert = `-----BEGIN CERTIFICATE-----
MIIGXDCCBUSgAwIBAgIBCjANBgkqhkiG9w0BAQUFADB/MQswCQYDVQQGEwJFVTEn
MCUGA1UEChMeQUMgQ2FtZXJmaXJtYSBTQSBDSUYgQTgyNzQzMjg3MSMwIQYDVQQL
ExpodHRwOi8vd3d3LmNoYW1iZXJzaWduLm9yZzEiMCAGA1UEAxMZQ2hhbWJlcnMg
b2YgQ29tbWVyY2UgUm9vdDAeFw0wOTAxMjAxMDE4MTJaFw0xOTAxMTgxMDE4MTJa
MIH9MQswCQYDVQQGEwJFUzEiMCAGCSqGSIb3DQEJARYTaW5mb0BjYW1lcmZpcm1h
LmNvbTFDMEEGA1UEBxM6TWFkcmlkIChzZWUgY3VycmVudCBhZGRyZXNzIGF0IHd3
dy5jYW1lcmZpcm1hLmNvbS9hZGRyZXNzKTESMBAGA1UEBRMJQTgyNzQzMjg3MSIw
IAYDVQQLExlodHRwOi8vd3d3LmNhbWVyZmlybWEuY29tMRkwFwYDVQQKExBBQyBD
YW1lcmZpcm1hIFNBMTIwMAYDVQQDEylBQyBDYW1lcmZpcm1hIEV4cHJlc3MgQ29y
cG9yYXRlIFNlcnZlciB2MzCCASAwDQYJKoZIhvcNAQEBBQADggENADCCAQgCggEB
AIg1c+SE9a2pYYPrVGr9c+aEjvoUncE2WhlZhuKzfxwF5YSV1UfGmPupAgy1yILQ
cTUd2M2bqCzInVZ0aLJQ5MmmG0dfzq4EFh/apTyTMcNrfoN9ocafuEwCYxLAyhh9
JHqRyOzkjWLpyI2Xw1w5vTWESGVNDVcAm5eEMIGSnWsLqjOJaXd4QwXvy4CQi//j
FRIZD2nP6xyJlLHdYxpbfETAqyea4loU+E0oy5PxJQlB9xE7BqmmpviV2SHFTPd/
VnX9/AAJPOM0bEvVCauDojwLCqp+8N+rEEaAnO8U2c4N3lZVuRXkc9ykg7hSkABh
cMDOyMdfS8aeGNdNG7lMzFECAQOjggJkMIICYDASBgNVHRMBAf8ECDAGAQH/AgEC
MG4GA1UdHwRnMGUwMKAuoCyGKmh0dHA6Ly9jcmwuY2FtZXJmaXJtYS5jb20vY2hh
bWJlcnNyb290LmNybDAxoC+gLYYraHR0cDovL2NybDEuY2FtZXJmaXJtYS5jb20v
Y2hhbWJlcnNyb290LmNybDAdBgNVHQ4EFgQUCkrAypgS75dZ3fekr7AUpDmurkow
dQYIKwYBBQUHAQEEaTBnMD0GCCsGAQUFBzAChjFodHRwOi8vd3d3LmNhbWVyZmly
bWEuY29tL2NlcnRzL1JPT1QtQ0hBTUJFUlMuY3J0MCYGCCsGAQUFBzABhhpodHRw
Oi8vb2NzcC5jYW1lcmZpcm1hLmNvbTCBqwYDVR0jBIGjMIGggBTjlPWxTenboSlb
V4tNdgZ24dGiiqGBhKSBgTB/MQswCQYDVQQGEwJFVTEnMCUGA1UEChMeQUMgQ2Ft
ZXJmaXJtYSBTQSBDSUYgQTgyNzQzMjg3MSMwIQYDVQQLExpodHRwOi8vd3d3LmNo
YW1iZXJzaWduLm9yZzEiMCAGA1UEAxMZQ2hhbWJlcnMgb2YgQ29tbWVyY2UgUm9v
dIIBADAOBgNVHQ8BAf8EBAMCAQYwHgYDVR0RBBcwFYETaW5mb0BjYW1lcmZpcm1h
LmNvbTAnBgNVHRIEIDAegRxjaGFtYmVyc3Jvb3RAY2hhbWJlcnNpZ24ub3JnMD0G
A1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIBFhxodHRwOi8vcG9saWN5LmNh
bWVyZmlybWEuY29tMA0GCSqGSIb3DQEBBQUAA4IBAQAw33XPOfeYIQuMozpM10jQ
4QtoJC+GeZUuAuMw0Yg+Klhipr+gOx6nHmpnNptChWcad97BZdY1xQPcGUmHXHBg
E1QOMDE5e7lakHyhs2su0QK6fFTFC+xhWr5gGY9fxS6JFwzOrYIEV9hktMl9Z/K0
/Z5beZ4vocqq47R/R3pem5d1YSGviayQrjKsWdTUZTk57p+oKb3QhuRhRS80tOTT
9xmhmt3YwUUT+FZhBPPfrlZtJb3PDNVCjgYyBynDj7VjIsfGxZgogisO+84LhEp2
UcXy2I2PbqLy7XRzPRxJKcRgbooFzC9iuY5ZcFJB9JLqo57rtZimNjNwLoO8sifX
-----END CERTIFICATE-----
`

const issuer = `MH8xCzAJBgNVBAYTAkVVMScwJQYDVQQKEx5BQyBDYW1lcmZpcm1hIFNBIENJRiBBODI3NDMyODcxIzAhBgNVBAsTGmh0dHA6Ly93d3cuY2hhbWJlcnNpZ24ub3JnMSIwIAYDVQQDExlDaGFtYmVycyBvZiBDb21tZXJjZSBSb290`
const serial = `Cg==`

func TestCert(t *testing.T) {
	p, _ := pem.Decode([]byte(cert))
	c, _ := x509.ParseCertificate(p.Bytes)
	t.Log(c.Issuer.ToRDNSequence())

	i, _ := base64.StdEncoding.DecodeString(issuer)
	var name pkix.RDNSequence
	asn1.Unmarshal(i, &name)

	//t.Log(reflect.DeepEqual(i, c.Issuer.ToRDNSequence()))
	t.Logf("%s", c.Issuer.ToRDNSequence())

	t.Log(name.String())
	t.Log(c.Issuer.ToRDNSequence().String() == name.String())

	s, _ := base64.StdEncoding.DecodeString(serial)
	h := fmt.Sprintf("%X", s)
	t.Logf("%s, %X", strings.TrimLeft(h, "0"), c.SerialNumber.Bytes())
	t.Log(len(c.Issuer.ToRDNSequence()))

	t.Log(comp(c.Issuer.ToRDNSequence(), name))
}

func comp(a, b pkix.RDNSequence) bool {
	if len(a) != len(b) {
		return false
	}
	needed := len(a)
	matched := 0
	for _, i := range a {
		for _, j := range b {
			if compset(i, j) {
				matched += 1
				goto CONTINUE
			}
		}
		return false
	CONTINUE:
	}
	return matched == needed
}

func compset(a, b pkix.RelativeDistinguishedNameSET) bool {
	if len(a) != len(b) {
		return false
	}
	sort.Slice(a, func(i, j int) bool {
		if len(a[i].Type) < len(b[j].Type) {
			return true
		}
		for index, value := range a[i].Type {
			if value < b[j].Type[index] {
				return true
			}
		}
		return false
	})
	sort.Slice(b, func(i, j int) bool {
		if len(a[i].Type) < len(b[j].Type) {
			return true
		}
		for index, value := range a[i].Type {
			if value < b[j].Type[index] {
				return true
			}
		}
		return false
	})

	return reflect.DeepEqual(a, b)
	//if len(a) != len(b) {
	//	return false
	//}
	//needed := len(a)
	//matched := 0
	//for _, i := range a {
	//	for _, j := range b {
	//		if reflect.DeepEqual(i, j) {
	//			matched += 1
	//			goto CONTINUE
	//		}
	//	}
	//	return false
	//CONTINUE:
	//}
	//return matched == needed
}

var r = regexp.MustCompilePOSIX(`^0{2}*`)

func TestASdASD(t *testing.T) {
	a := "0A"
	t.Log(r.ReplaceAllString(a, ""))
}

const bad = `-----BEGIN CERTIFICATE-----
MIIH4jCCBcqgAwIBAgIUZ6RtH7xmDM0r66IKSlpCZNrlRfYwDQYJKoZIhvcNAQEF
BQAwRTELMAkGA1UEBhMCQk0xGTAXBgNVBAoTEFF1b1ZhZGlzIExpbWl0ZWQxGzAZ
BgNVBAMTElF1b1ZhZGlzIFJvb3QgQ0EgMzAeFw0xNDA1MDcxMzEyMDNaFw0yNDA1
MDcxMzEyMDNaMEYxCzAJBgNVBAYTAkNIMQ8wDQYDVQQIEwZMdXplcm4xDTALBgNV
BAoTBFN1dmExFzAVBgNVBAMTDlN1dmEgUm9vdCBDQSAxMIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEA9KfSFwpwbRnrfnMk1DkKQguwEKg6crSLKS31CU9E
ShdmIzMQyo9k4doec6c0cpubk17VlEEE8SmFSqwmLBRo+65kR5c3X4MeI0Fv1ZXH
WV+ZiaK+CVPf4OFNNCNuEFc1qnNxyWGvGVI+KMk1Lmrpda6h5GkMpFdxBRGq4RkU
aw41ljJgY9+UapZTl0b39XEeEgQshY/hKEKPeRZNeTHBFWFTsAZxZBSH0bz35zfh
X1oQLad3b5Q2Nw1utEcai4I9DnTyAQ7wRtius217twXERdpeLdTurKe7TVqHcyBS
ziTpsCewINJ1S69a1E7Z59SNorOEgGIS2Z89fIlwYVQkcW5pLZL+Q5UC1rcD/FWq
m4rIOrjM0AYcLEiScmNYYgLEPrXvh1BVMkc+SIqiQ7JhlzXSDZmMBcqrlVilp2oz
lyuCRlMpGdlUqe0BD3JY/vfOZRm+NHfys4mmLIQhLJgX2vH5UOeAzdQ2pkpFdHNq
1tMLITr108NcZ62updidyVFy+8kbr7NKawmp03MtYjdYqEi2lDNgJcwk17uoxhbv
LEYvSNM+wMc73duO97pOrgbTrIIHeBdgjP/ZqHkW/4ZtxUpxFSxqoBgUVw6IHTn9
2cYBmouDdhEYhnFhcEVqYP5N0JjT9nFzWL/EU+Lgk8y3x59luxaGJV9tEU9P0MIy
cBUCAwEAAaOCAscwggLDMBIGA1UdEwEB/wQIMAYBAf8CAQEwcwYIKwYBBQUHAQEE
ZzBlMCsGCCsGAQUFBzABhh9odHRwOi8vb2NzcC5xdW92YWRpc2dsb2JhbC5jb20v
MDYGCCsGAQUFBzAChipodHRwOi8vdHJ1c3QucXVvdmFkaXNnbG9iYWwuY29tL3F2
cmNhMy5jcnQwgdAGA1UdIASByDCBxTCBwgYMKwYBBAG+WAADhFgAMIGxMIGDBggr
BgEFBQcCAjB3GnVBbnkgdXNlIG9mIHRoaXMgQ2VydGlmaWNhdGUgY29uc3RpdHV0
ZXMgYWNjZXB0YW5jZSBvZiB0aGUgU3V2YSBDZXJ0aWZpY2F0ZSBQb2xpY3kgLyBD
ZXJ0aWZpY2F0aW9uIFByYWN0aWNlIFN0YXRlbWVudC4wKQYIKwYBBQUHAgEWHWh0
dHA6Ly9wa2kuc3V2YS5jaC9yZXBvc2l0b3J5MGQGA1UdHgRdMFugWTAKgQhAc3V2
YS5jaDANgQtAc3V2YW5ldC5jaDAPgQ1Ac3V2YW5ldDYyLmNoMA+BDUBzdXZhbmV0
NzcuY2gwDIEKQHN1dmE2Mi5jaDAMgQpAc3V2YTc3LmNoMA4GA1UdDwEB/wQEAwIB
BjB0BgNVHSUEbTBrBggrBgEFBQcDBAYIKwYBBQUHAwIGCCsGAQUFBwMJBgorBgEE
AYI3CgMEBgorBgEEAYI3FAICBgorBgEEAYI3FAIBBgcrBgEFAgMFBggrBgEFBQgC
AgYJKwYBBAGCNxUFBgkrBgEEAYI3FQYwHwYDVR0jBBgwFoAU8sAT4IJDPvvuL2cy
ljVc27jLAtAwOQYDVR0fBDIwMDAuoCygKoYoaHR0cDovL2NybC5xdW92YWRpc2ds
b2JhbC5jb20vcXZyY2EzLmNybDAdBgNVHQ4EFgQUPFQUaTyz0/rgxsL2+kdFRxXK
KmowDQYJKoZIhvcNAQEFBQADggIBADsk54ImQSM2LcLtwpH5s3NPn/qpua22SUyH
sujqy8vHEAOS0KPbN+Jnq4KpexylTVHQ3ybgHSQt6SZ+/NSBHO8eAAyqZyWjenyk
UCcL7TNO82tD7lkuq+eo+BIsq9AJTI0gGRqG/wFyvNpVssZ0bFdqGNq0aM74NHWD
7LRa6toC1I+YNpvelSlZvGfEpm0G7e04AE3kzFnaemG3RwRY2mUtT5Aby5vpfouh
IbdF4t1NEyC9ExFOkEjZ3P1AAoJgxQC3T7B1Mo6r03pcBdd9LrjjVJidUyj+j/ha
faZo4e1wJeU09UtzVSzGb1GA8QHOJMY7VeA0qLg4qfZdeoDxrCZJKn/pZP2D6dQs
0Za1args4EUJmdVFsuFNc1DsM1EXTD5o9dHkX/cKPv6eMRehP7emNjJgmcIv1rX3
sotSJA06D+5LW6ZkuWdS2uArCta8YgrVtefRMNj2nhVGafLt7tE819E0fqnaknGR
RgfNRFEMeTIU29RtgvzbpYtCK+O1v7a3x55mt/RbMhtruns3OOVAY+l7nW1y51Xb
A8bPOZc7fREndSacNCpK37Or3AhE4Uneylz+rN25H2hL8OT/xAXxj6IcPRuD2SDH
nvXiM0xeqCQpfDNv/35uNSMdpsA75GZwRpvt0fMc5r0AwtwBFZX7X4KtULoNxLNb
JZxATf23
-----END CERTIFICATE-----
`

const space = `-----BEGIN CERTIFICATE-----
MIIPhDCCDmygAwIBAgIRQM1zZ4GZ4gfwpQtUYye3Ne0wDQYJKoZIhvcNAQEFBQAw
XDELMAkGA1UEBhMCQkUxFTATBgNVBAsTDFRydXN0ZWQgUm9vdDEZMBcGA1UEChMQ
R2xvYmFsU2lnbiBudi1zYTEbMBkGA1UEAxMSVHJ1c3RlZCBSb290IENBIEcyMB4X
DTEzMDcxNjAwMDAwMFoXDTE4MDcxNjAwMDAwMFowbDELMAkGA1UEBhMCREUxHDAa
BgNVBAgTE05vcmRyaGVpbi1XZXN0ZmFsZW4xDTALBgNVBAcTBEJvbm4xFjAUBgNV
BAoTDURldXRzY2hlIFBvc3QxGDAWBgNVBAMTD0RQREhMIFRMUyBDQSBJMzCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALgmkAt1Z2MGFEy0Y/sUmbG/uY2R
4oUfgKqdq2W9kNtjhWmVUDogXW9ZMMnckOwjgAJq7A9p3ZV7T/akbf9L0x1nH3aq
B+AB4X41UJq4+7TD0hH21E17UQFYmcu+HjhJ+yC7MppNIUCMqHZSpsPs4XAdaxGu
iCIMMrLkXAsQC9cgud+sam1ioS8rU50DJdP889RBqFfS/DYLrZUcpJEFpKv6pn/T
/o24Szqyn9mNNo9gz9Hw47ppyeG7EkFm4L96kZ27KcKOtMPsGBfH+AGFg40ecVCj
n3zeQO4ryMhcQLK8PpBxNnA+OjcLyNrkOWpbwLXmbfmfRU4XG1u+25QMwlcCAwEA
AaOCDC8wggwrMA4GA1UdDwEB/wQEAwIBBjBXBgNVHSAEUDBOMAgGBmeBDAECAjBC
BgorBgEEAaAyATwBMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNp
Z24uY29tL3JlcG9zaXRvcnkvMBIGA1UdEwEB/wQIMAYBAf8CAQAwggp7BgNVHR4E
ggpyMIIKbqCCCjgwEYIPYWRyZXNzZGlhbG9nLmRlMBSCEmFkcmVzcy1yZXNlYXJj
aC5kZTAQgg5hZXJvbG9naWMuYWVybzARgg9hbGxlc25lYmVuYW4uZGUwE4IRY2F0
aGF5cGFjaWZpYy5jb20wD4INY2xlYXItbWFpbC5kZTAMggpjbGl4bWl4LmRlMAqC
CGNvdmlzLmRlMBGCD2RldXRzY2hlcG9zdC5kZTAUghJkZXV0c2NoZXBvc3QubG9j
YWwwHYIbZGV1dHNjaGVwb3N0LXNhZmUtb25saW5lLmRlMByCGmRldXRzY2hlLXNh
bW1sZXJtdWVuemVuLmRlMAiCBmRobC5hdDAIggZkaGwuY2gwC4IJZGhsLmNvLnVr
MAmCB2RobC5jb20wDIIKZGhsLmNvbS5jbzAMggpkaGwuY29tLmhrMAyCCmRobC5j
b20ucGwwCIIGZGhsLmRlMAiCBmRobC5lZTAIggZkaGwuZXMwCIIGZGhsLm5sMA+C
DWRobGJlbmVsdXgubmwwGIIWZGhsLWJ1c2luZXNzcG9ydGFsLmNvbTAYghZkaGwt
Y29ycG9yYXRlLXdlYXIuY29tMBGCD2RobGRhc2hib2FyZC5zZTATghFkaGwtZGVs
aXZlcm5vdy5kZTAWghRkaGxldXJvbmV0c3RhdHVzLmNvbTATghFkaGxleHByZXNz
ZWFzeS5zZTARgg9kaGxleHRlcm5hbC5jb20wD4INZGhsZnJlaWdodC5kazAPgg1k
aGxmcmVpZ2h0LmVlMA+CDWRobGZyZWlnaHQuZmkwD4INZGhsZnJlaWdodC5sdjAP
gg1kaGxmcmVpZ2h0Lm5vMA+CDWRobGZyZWlnaHQuc2UwH4IdZGhsLWdlc2NoYWVm
dHNrdW5kZW5wb3J0YWwuZGUwFYITZGhsZ2xvYmFsbWFpbC5jby51azATghFkaGxn
bG9iYWxtYWlsLmNvbTAUghJkaGwtZ2xvYmFsbWFpbC5jb20wDoIMZGhsaXRub3cu
Y29tMBuCGWRobC1rdW5kZW5hdWZzY2hhbHR1bmcuZGUwFYITZGhsc2VydmljZWNl
bnRlci5zZTAUghJkaGxzZXJ2aWNlcG9pbnQuc2UwEIIOZGhsc2VydmljZXMuaXQw
DYILZGhsdHdlYi5jb20wDYILZGhsLXVzYS5jb20wFoIUZGhsLXZlcnNhbmRwb3J0
YWwuZGUwE4IRZGhsLXdlYmNoZWNrZXIuZGUwEIIOZGhsd2VicG9ydC5jb20wGYIX
ZGllbnN0bGVpc3RlcmthdGFsb2cuZGUwEYIPZGllcmVkYWt0aW9uLmRlMBqCGGRp
cmVrdG1hcmtldGluZ2NlbnRlci5kZTAPgg1kaXJla3RwbHVzLmRlMAqCCGRwY29t
LmRlMAuCCWRwZGhsLmNvbTAMggpkcC1kaGwuY29tMAqCCGRwZGhsLmRlMAuCCWRw
LWRobC5kZTATghFkcC1pdHNvbHV0aW9ucy5kZTAKgghkcHduLmNvbTAJggdkcHdu
LmRlMAqCCGRwd24ubmV0MA2CC2Rwd25yZWYuY29tMA+CDWUtZGF0YWdhdGUuZGUw
DYILZWZpbGlhbGUuZGUwE4IRZWlua2F1ZmFrdHVlbGwuZGUwCoIIZXBvc3QuZGUw
DoIMZXBvc3QtZ2thLmRlMAqCCGV4ZWwuY29tMBCCDmV4cHJlc3NlYXN5LnNlMBiC
FmZpbGlhbGtvbW11bmlrYXRpb24uZGUwDoIMZm9ydW1nZWxiLmRlMBSCEmdsb2Jh
bG1haWwtcGl0LmNvbTAQgg5pYmdzdGFyc2hvcC5pdDAOggxpbnRyYXNoaXAuY2gw
DoIMaW50cmFzaGlwLmRlMBKCEGludHJhc2hpcC1kaGwuYXQwEoIQaW50cmFzaGlw
LWRobC5iZTAVghNpbnRyYXNoaXAtZGhsLmNvLnVrMBKCEGludHJhc2hpcC1kaGwu
ZWUwEoIQaW50cmFzaGlwLWRobC5maTASghBpbnRyYXNoaXAtZGhsLmdyMBKCEGlu
dHJhc2hpcC1kaGwuaWUwEoIQaW50cmFzaGlwLWRobC5sdDASghBpbnRyYXNoaXAt
ZGhsLmx1MBKCEGludHJhc2hpcC1kaGwubHYwEoIQaW50cmFzaGlwLWRobC5ubDAP
gg1sZXNlcmtpb3NrLmRlMBGCD2xlc2Vyc2VydmljZS5kZTAYghZsZXNlcnNlcnZp
Y2UtbWVkaWEuZGUgMCGCH2xlc2Vyc2VydmljZS1zaWNoZXJoZWl0c2Fiby5kZSAw
DoIMbGV0dGVybmV0LmRlMBGCD2xldHRlcm5ldC1iby5kZTATghFsZXR0ZXJuZXQt
cmVmLmRlIDATghFtYWlsaW5nZmFjdG9yeS5kZTAOggxtZWRpYW1haWwuZGUwDoIM
bWVpbnBha2V0LmRlMAuCCW1yc2MuaW5mbzASghBteWJpbGwuZGhsLmNvLmlsMBeC
FW9ubGluZWZyYW5raWVydW5nLmRlIDAQgg5wYWNrc3RhdGlvbi5kZTAKgghwYWtl
dC5kZTAggh5wYXJ0bmVycG9ydGFsLWRldXRzY2hlcG9zdC5kZSAwFIIScG9ydG9r
YWxrdWxhdG9yLmRlMAmCB3Bvc3QuZGUwD4INcG9zdGFkcmVzcy5kZTAPgg1wb3N0
ZGlyZWt0LmRlMBOCEXBvc3RvZmZpY2VzaG9wLmRlMBaCFHBvc3QtcGFydG5lci1z
aG9wLmRlMA2CC3ByaW50Y29tLmRlMA+CDXByaW50dHJhY2suZGUwE4IRcmVudGVu
c2VydmljZS5jb20wEoIQc2NocmVpYmNlbnRlci5kZTAdghtzbWFydHNlbnNvci10
ZW1wZXJhdHVyZS5uZXQwFIISc29jaWFsbWVtb3JpZXMuY29tMA6CDHRlbGVncmFt
bS5kZTAIggZ2Z2wubmwwCYIHd2xkcy5kZTAYghZ3b3JsZHNlcnZpY2VjZW50cmUu
Y29tMA6CDGJsdWVkYXJ0LmNvbTAOggxkaGwtZXNoaXAubmwwD4INZGhsLWV0cmFj
ay5ubDAWghRkaGwtaW50ZXJuZXR0cmFjay5ubDAWghRkaGxyZXRvdXJvcGRyYWNo
dC5ubDARgg9kaGxzcGVlZHBhY2suYmUwEYIPZGhsLXRyYWNrbmV0Lm5sMBKCEGlu
dHJhc2hpcC1kaGwuaHUwEYIPc2VydmljZXBvaW50LnNlMA2CC3VtemllaGVuLmRl
MFmkVzBVMQswCQYDVQQGEwJERTEcMBoGA1UECBMTTm9yZHJoZWluLVdlc3RmYWxl
bjENMAsGA1UEBxMEQm9ubjEZMBcGA1UEChMQRGV1dHNjaGUgUG9zdCBBRzBWpFQw
UjELMAkGA1UEBhMCREUxHDAaBgNVBAgTE05vcmRyaGVpbi1XZXN0ZmFsZW4xDTAL
BgNVBAcTBEJvbm4xFjAUBgNVBAoTDURldXRzY2hlIFBvc3ShMDAKhwgAAAAAAAAA
ADAihyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAnBgNVHSUEIDAe
BggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMJMD0GA1UdHwQ2MDQwMqAwoC6G
LGh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3MvdHJ1c3Ryb290ZzIuY3JsMIGE
BggrBgEFBQcBAQR4MHYwMwYIKwYBBQUHMAGGJ2h0dHA6Ly9vY3NwMi5nbG9iYWxz
aWduLmNvbS90cnVzdHJvb3RnMjA/BggrBgEFBQcwAoYzaHR0cDovL3NlY3VyZS5n
bG9iYWxzaWduLmNvbS9jYWNlcnQvdHJ1c3Ryb290ZzIuY3J0MB0GA1UdDgQWBBTI
AwLewLGrg8Ue/gf3eL3lgwSIfTAfBgNVHSMEGDAWgBQU9uWLMbZFgEpMbfzCh4nK
NsOQYjANBgkqhkiG9w0BAQUFAAOCAQEAkc0t50j0hsGe6IcFlXh7oX4HAcEbai3z
mcQTwcGcmpFZQWiSKM8BPsdp502QSANyYf5IfywVUN+X22JIumb/Rkl0GGSZMGh/
a3yvVK0iBfNHxSr9EoE8TxTMlzT4WhQAC0QZ+SHts49d3haFohkM04q4zHKl5zq/
apDigTUgPf7MwT87LfqTxhbJa4TwoWBgyVqSs1zS9noGcbjUMSEsTcRjeM9GVs2v
0ZOkDABycGEQ40peJTGJZAM2XGdKAq5Tlt++8yaMY3FUzhWS00JW8ff90gMtIxgP
Vpmh/e9DOQifITme0e6n12q7yO9zhGwNLf5SsdR+JsLLW0VnRWvPjg==
-----END CERTIFICATE-----
`

func TestWat(t *testing.T) {
	b, _ := pem.Decode([]byte(space))
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(c.Issuer)
}
