package main // import "whatever"
import (
	"bufio"
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
)

const cert = `-----BEGIN CERTIFICATE-----
MIIDqDCCApCgAwIBAgIRALAVZoQ6S8e1Dth48I7yF6UwDQYJKoZIhvcNAQEFBQAw
NDETMBEGA1UEAxMKQ29tU2lnbiBDQTEQMA4GA1UEChMHQ29tU2lnbjELMAkGA1UE
BhMCSUwwHhcNMDUwOTIxMTY0MTI1WhcNMTUwOTMwMTY0MTE2WjBIMQswCQYDVQQG
EwJJTDEhMB8GA1UEChMYQmFuayBMZXVtaSBMZS1Jc3JhZWwgTFREMRYwFAYDVQQD
Ew1CYW5rIExldW1pIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
yTkpwkOCkDfBp5Lim/TwTPg3/1fV9/yhV6AHCVSz1tgCqkZMwVzEAPrK4pks+nbS
t+8B/1V7GcB3Ex6v26twWRBQTmOi6L9llVWMoXKtoiKZ7F+REygbt0mCceZpa66G
FATmK3uUXdrzawdYfZEZd7dE8e3ZhGdn4IxgHfJCo8iLLXPlgg063iHKdOvaWLsM
6cl6VvwcQn7jgWvFBDEe1NgeT1lHh2J3fAh/Qy223yB7EMKT+6PyA6fUpKhKwGqH
r+bizyNYel8cdDoELytgNAZa97lBtu4OrCFiTCW81hvCTsgRzG1Z2woZgwylxZDi
XjdbJ68CCiuQ0HPzDiey2QIDAQABo4GgMIGdMAwGA1UdEwQFMAMBAf8wPQYDVR0f
BDYwNDAyoDCgLoYsaHR0cDovL2ZlZGlyLmNvbXNpZ24uY28uaWwvY3JsL0NvbVNp
Z25DQS5jcmwwDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBRHGOgcgJJgpXLGBwCl
mZApp9owxzAfBgNVHSMEGDAWgBRLAZs+VhplNnbLe5eqkgXuMucoMTANBgkqhkiG
9w0BAQUFAAOCAQEAnxgN7ZqjwcbmY3rXs9ylpsJW1bz+lGlXlBYiHq4nQooOiPBj
FbVqosfcke9VfgMbNRtUwz2blUslSXETT7jcZbpQqVHDEpbttTPmc2oAW8ZvnxA5
FdXxuIxneB1UbcdVKHes+VGSnrAL4ExXz348K8g3JwNSxMnfVzfifnjve/mFxxoH
Ii98H8gAksgWw+wQWeLYz3YNxqrcVOmutadk5ZKSsp5Xwnz1WZTslbbPWZkUELLI
sg72160h6gZ7z033kZpclagkE1UZaAuKy/pnwJeYArDwHUD0lQrfW9/rQFo4def4
OO3uKz3ooLHXkbd84k3j0HuDBb8D21CltgYWgw==
-----END CERTIFICATE-----`

//type Shim struct {
//	Names      []NameShimSET
//}

type Shim []NameShimSET

func NewShim(names []pkix.AttributeTypeAndValue) []NameShimSET {
	shim := make([]NameShimSET, 0)
	for _, n := range names {
		shim = append(shim, NameShimSET{n})
	}
	return shim
}

type NameShimSET []pkix.AttributeTypeAndValue

//
//type NameShimSET struct {
//	Name      pkix.AttributeTypeAndValue `asn1:"set"`
//}

type lol struct {
}

func (shim NameShimSET) String() interface{} {
	return fmt.Sprintf("%v", shim)
}

func (shim Shim) String() interface{} {
	return fmt.Sprintf("%v", shim)
}

func main() {
	r := bufio.NewReader(os.Stdin)
	w := json.NewEncoder(os.Stdout)
	newline := []byte(fmt.Sprintln("-1"))
	for line, err := r.ReadBytes('\n'); err == nil && !reflect.DeepEqual(line, newline); line, err = r.ReadBytes('\n') {
		fmt.Printf("%s\n", line)
		err := w.Encode(doit(bytes.TrimRight(line, "\n")))
		if err != nil {
			panic(err)
		}
	}
	//thing := "MHwxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjEYMBYGA1UECgwPU1NMIENvcnBvcmF0aW9uMTEwLwYDVQQDDChTU0wuY29tIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgUlNB"
	//out, err := doit([]byte(thing))
	//fmt.Println(out)
	//fmt.Println(err)
	//block, _ := pem.Decode([]byte(cert))
	//c, er := x509.ParseCertificate(block.Bytes)
	//if er != nil {
	//	panic(er)
	//}
	////println(c.Issuer.String())
	//shim := NewShim(c.Issuer.Names)
	//res, err := asn1.Marshal(shim)
	//if err != nil {
	//	println(res)
	//}
	//println(string(res))
	//
	//out := base64.StdEncoding.EncodeToString(res)
	//println(out)
	//
	//thing := "MHwxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjEYMBYGA1UECgwPU1NMIENvcnBvcmF0aW9uMTEwLwYDVQQDDChTU0wuY29tIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgUlNB"
	//d := make([]byte, len(thing))
	//_, err = base64.StdEncoding.Decode(d, []byte(thing))
	//if err != nil {
	//	panic(err)
	//}
	//var name pkix.RDNSequence
	//println(d)
	//_, err = asn1.Unmarshal(d, &name)
	//if err != nil {
	//	panic(err)
	//}
	//name.String()
	//for _, r := range name {
	//	for _, attr := range r {
	//		if attr.Type.Equal([]int{2, 5, 4, 10}) {
	//			fmt.Printf("%s\n",attr.Value)
	//		}
	//		if attr.Type.Equal([]int{2, 5, 4, 3}) {
	//			fmt.Printf("%s\n", attr.Value)
	//		}
	//	}
	//}
}

type Deserialized struct {
	CommonName   string
	Organization string
	Err          error
}

func doit(issuer []byte) (d Deserialized) {
	rawBytes := make([]byte, base64.StdEncoding.DecodedLen(len(issuer)))
	_, d.Err = base64.StdEncoding.Decode(rawBytes, issuer)
	if d.Err != nil {
		return
	}
	var name pkix.RDNSequence
	_, d.Err = asn1.Unmarshal(rawBytes, &name)
	if d.Err != nil {
		return
	}
	for _, r := range name {
		for _, attr := range r {
			if attr.Type.Equal([]int{2, 5, 4, 10}) {
				d.CommonName = fmt.Sprint(attr.Value)
				//fmt.Printf("%s\n",attr.Value)
			} else if attr.Type.Equal([]int{2, 5, 4, 3}) {
				d.Organization = fmt.Sprint(attr.Value)
				//fmt.Printf("%s\n", attr.Value)
			}
		}
	}
	return
}
