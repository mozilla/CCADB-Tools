package main // import "github.com/mozilla/CCADB-Tools"
import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

const str = `MEUxCzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcxHzAdBgNVBAMTFlN3aXNzU2lnbiBHb2xkIENBIC0gRzI=`

func get() []byte {
	resp, err := http.Get("https://hg.mozilla.org/mozilla-central/raw-file/tip/security/certverifier/ExtendedValidation.cpp")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return b
}

const canary = `static const struct EVInfo kEVInfos.*\n(.*\n)*};`

//const commentsAndDebugPragmas = `[//.*\n|#ifdef DEBUG\n(.*\n)#endif\n]`
const commentsAndDebugPragmas = `(//.*\n|#ifdef DEBUG.*\n(.*\n)*#endif)`

const multlineString = `"\n`
const joinMultiLine = `"\s*"`

func extract(src []byte) {
	r, err := regexp.Compile(canary)
	if err != nil {
		panic(err)
	}
	b := r.Find(src)
	//fmt.Println(string(b))
	r, err = regexp.Compile(commentsAndDebugPragmas)
	b = r.ReplaceAll(b, []byte{})
	//fmt.Println(string(b))
	r, err = regexp.Compile(multlineString)
	b = r.ReplaceAll(b, []byte{'"'})
	//fmt.Println(string(b))
	r, err = regexp.Compile(joinMultiLine)
	b = r.ReplaceAll(b, []byte{})
	//fmt.Println(string(b))
	deser(b)
}

type EVInfo struct {
	dottedOid         string
	oidName           string
	sha256Fingerprint string
	issuer            string
	serial            string
}

func deser(src []byte) {
	r := bytes.NewReader(src)
	var b rune
	var err error
	for b, _, err = r.ReadRune(); err == nil && b != '{'; b, _, err = r.ReadRune() {
	}
	if err != nil {
		panic(err)
	}
	//b, err = consumeWhiteSpace(r)
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Println(src)
	//fmt.Println(string(b))
	fmt.Println(string(src))
	for {
		b, _, err = r.ReadRune()
		switch err {
		case nil:
		case io.EOF:
			return
		default:
			panic(err)
		}
		switch b {
		case ' ', '\n':
		case '{':
			fmt.Println("YA")
			NewEVInfo(r)
		// deser
		case '}':
			return
		default:
			panic(b)
		}

	}
}

func NewEVInfo(r io.RuneReader) {
	dottedOid := extractStringField(r)
	fmt.Println(dottedOid)
	oidName := extractStringField(r)
	fmt.Println(oidName)
	fp := extractFingerprint(r)
	fmt.Println(fp)
	issuer := decodeIssuer(extractStringField(r))
	fmt.Println(issuer)
	serial := extractStringField(r)
	fmt.Println(serial)

	consumeWhiteSpace(r)
	r.ReadRune()

}

func decodeIssuer(i string) string {
	b, err := base64.StdEncoding.DecodeString(i)
	if err != nil {
		panic(err)
	}
	var issuer pkix.RDNSequence
	_, err = asn1.Unmarshal(b, &issuer)
	if err != nil {
		panic(err)
	}
	return issuer.String()
}

func extractFingerprint(r io.RuneReader) string {
	consumeWhiteSpace(r)
	str := strings.Builder{}
	for i := 0; i < 32; i++ {
		consumeWhiteSpace(r)
		r.ReadRune() // read x
		b, _, _ := r.ReadRune()
		str.WriteRune(b)
		b, _, _ = r.ReadRune()
		str.WriteRune(b)
		r.ReadRune() //,
	}
	r.ReadRune()
	r.ReadRune()
	return str.String()
}

func extractStringField(r io.RuneReader) string {
	b, err := consumeWhiteSpace(r)
	if err != nil {
		panic(err)
	}
	if b != '"' {
		panic("unexpected byte")
	}
	str := strings.Builder{}
	for b, _, err = r.ReadRune(); err == nil && b != '"'; b, _, err = r.ReadRune() {
		_, er := str.WriteRune(b)
		if er != nil {
			panic(err)
		}
	}
	b, _, err = r.ReadRune()
	if err != nil {
		panic(err)
	}
	if b != ',' {
		panic("unexpected byte")
	}
	return str.String()
}

func consumeWhiteSpace(r io.RuneReader) (rune, error) {
	var b rune
	var err error
	for b, _, err = r.ReadRune(); err == nil; b, _, err = r.ReadRune() {
		switch b {
		case ' ', '\n':
		default:
			return b, err
		}
	}
	return b, err
}

//{ 0xBC, 0x4D, 0x80, 0x9B, 0x15, 0x18, 0x9D, 0x78, 0xDB, 0x3E, 0x1D,
//  0x8C, 0xF4, 0xF9, 0x72, 0x6A, 0x79, 0x5D, 0xA1, 0x64, 0x3C, 0xA5,
//  0xF1, 0x35, 0x8E, 0x1D, 0xDB, 0x0E, 0xDC, 0x0D, 0x7E, 0xB3 },

func main() {
	//_, err := hex.DecodeString("BC")
	//if err != nil {
	//	panic(err)
	//}
	extract(get())
}
