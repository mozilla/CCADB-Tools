/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main // import "github.com/mozilla/CCADB-Tools"
import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const nightly = "https://hg.mozilla.org/mozilla-unified/raw-file/central/security/certverifier/ExtendedValidation.cpp"
const beta    = "https://hg.mozilla.org/mozilla-unified/raw-file/beta/security/certverifier/ExtendedValidation.cpp"
const release = "https://hg.mozilla.org/mozilla-unified/raw-file/release/security/certverifier/ExtendedValidation.cpp"

func get(url string) ([]byte, error) {
	client := http.Client{}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("X-Automated-Tool", "https://github.com/mozilla/CCADB-Tools/EVChecker")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// Yanks out the array literal of EVInfos.
var canary = regexp.MustCompile(`static const struct EVInfo kEVInfos.*\n(.*\n)*};`)

// Strips away all comments and DEBUG pragma blocks.
var commentsAndDebugPragmas = regexp.MustCompile(`(//.*\n|#ifdef DEBUG.*\n(.*\n)*#endif)`)

// Finds instances of multiline strings, E.G. any string literal this is followed by a raw newline.
var multlineString = regexp.MustCompile(`"\s*\n`)

// After putting all entries of a multiline string onto the same line, we need to strip away
// any spaces between the string entries as well as their internal quotation marks.
var joinMultiLine = regexp.MustCompile(`"\s*"`)

func extract(src []byte) ([]*EVInfo, error) {
	b := canary.Find(src)
	b = commentsAndDebugPragmas.ReplaceAll(b, []byte{})
	b = multlineString.ReplaceAll(b, []byte{'"'})
	b = joinMultiLine.ReplaceAll(b, []byte{})
	return deser(b)
}

type EVInfo struct {
	DottedOID         string
	OIDName           string
	SHA256Fingerprint string
	Issuer            string
	Serial            string
}

func deser(src []byte) ([]*EVInfo, error) {
	kEVinfos := make([]*EVInfo, 0)
	r := bytes.NewReader(src)
	var b rune
	var err error
	// consumes all declaration info up to the opening brace that starts the array literal.
	// 		I.E. static const struct .... {
	for b, _, err = r.ReadRune(); err == nil && b != '{'; b, _, err = r.ReadRune() {
	}
	if err != nil {
		return kEVinfos, errors.Wrap(err, "failed to begin reading the kEVinfos array")
	}
	for {
		b, err := consumeWhiteSpace(r)
		if err != nil {
			return kEVinfos, err
		}
		switch b {
		case '{':
			// Begin an EVInfo object boundary.
			evinfo, err := NewEVInfo(r)
			if err != nil {
				return kEVinfos, err
			}
			kEVinfos = append(kEVinfos, evinfo)
  // After a struct '}', accept either ',' (more) or '}' (end-of-array)
+      if b, err = consumeWhiteSpace(r); err != nil {
+        return kEVinfos, err
+      }
+      if b == ',' {
+        continue
+      }
+      if b == '}' {
+        return kEVinfos, nil
+      }
+      return kEVinfos, errors.New(fmt.Sprintf(`received an unexpected character after EVInfo, got "%s"`, string(b)))
			case '}':
			// The end of the kEVinfo array
			return kEVinfos, nil
		default:
			return kEVinfos, errors.New(fmt.Sprintf(`received an unexpected character while parsing the kEVInfos array, got ""%s"`, string(b)))
		}

	}
}

func NewEVInfo(r io.RuneReader) (*EVInfo, error) {
	dottedOid, err := extractStringField(r)
	if err != nil {
		return nil, err
	}
	oidName, err := extractStringField(r)
	if err != nil {
		return nil, err
	}
	fp, err := extractFingerprint(r)
	if err != nil {
		return nil, err
	}
	issuer, err := extractStringField(r)
	if err != nil {
		return nil, err
	}
	issuer, err = decodeIssuer(issuer)
	if err != nil {
		return nil, err
	}
	serial, err := extractStringField(r)
	if err != nil {
		return nil, err
	}
	s, err := base64.StdEncoding.DecodeString(serial)
	if err != nil {
		return nil, err
	}
	// hex Serial number left padded with 0
	serial = fmt.Sprintf("%032X", s)
	brace, err := consumeWhiteSpace(r)
	if err != nil {
		return nil, err
	}
	if brace != '}' {
		return nil, errors.New(fmt.Sprintf("expected a closing brace for an EVInfo boundary, but got %s", string(brace)))
	}
	return &EVInfo{
		DottedOID:         dottedOid,
		OIDName:           oidName,
		SHA256Fingerprint: fp,
		Issuer:            issuer,
		Serial:            serial,
	}, nil
}

func decodeIssuer(i string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(i)
	if err != nil {
		return "", err
	}
	var issuer pkix.RDNSequence
	_, err = asn1.Unmarshal(b, &issuer)
	if err != nil {
		return "", err
	}
	return issuer.String(), nil
}

func extractFingerprint(r io.RuneReader) (string, error) {
	_, err := consumeWhiteSpace(r)
	if err != nil {
		return "", errors.Wrap(err, "failed to consume the whitespace prefixing a fingerprint")
	}
	str := strings.Builder{}
	for i := 0; i < 32; i++ {
		zero, err := consumeWhiteSpace(r)
		if err != nil {
			return "", errors.Wrap(err, "failed to consume whitespace while extracting fingerprint")
		}
		if zero != '0' {
			return "", errors.New(fmt.Sprintf(`Expected the character "0" while decoding hex, got "%s"`, string(zero)))
		}
		x, _, err := r.ReadRune() // read the x in 0xAA
		if err != nil {
			return "", errors.Wrap(err, `failed to read the "x" in a hex literal`)
		}
		if x != 'x' {
			return "", errors.New(fmt.Sprintf(`Expected the character "x" while decoding hex, got "%s"`, string(x)))
		}
		b, _, err := r.ReadRune() // get the upper byte of 0xAA
		if err != nil {
			return "", errors.Wrap(err, `failed to read the upper byte in a hex literal`)
		}
		str.WriteRune(b)
		b, _, err = r.ReadRune() // get the lower byte of 0xAA
		if err != nil {
			return "", errors.Wrap(err, `failed to read the lower byte in a hex literal`)
		}
		str.WriteRune(b)
		comma, _, err := r.ReadRune() // read the , in the array literal
		if err != nil {
			return "", errors.Wrap(err, `failed to read the hex literal array delimiter`)
		}
		if comma != ',' && comma != ' ' {
			return "", errors.New(fmt.Sprintf(`Expected the character "," or " " while decoding the internals of a hex array, got "%s"`, string(x)))
		}
	}
	brace, err := consumeWhiteSpace(r)
	if err != nil {
		return "", errors.Wrap(err, "failed to consume the closing brace while extracting a fingerprint")
	}
	if brace != '}' {
		return "", errors.New(fmt.Sprintf(`Expected the character "}" while decoding a hex array, got "%s"`, string(brace)))
	}
	comma, err := consumeWhiteSpace(r)
	if comma != ',' {
		return "", errors.New(fmt.Sprintf(`Expected the character "," while decoding the end of a hex array, got "%s"`, string(comma)))
	}
	return str.String(), nil
}

func extractStringField(r io.RuneReader) (string, error) {
	// consume whitespace up to the opening quote
	b, err := consumeWhiteSpace(r)
	if err != nil {
		return "", errors.Wrap(err, "failed to consume the leading whitespace before a string literal")
	}
	if b != '"' {
		return "", errors.New(fmt.Sprintf(`expected the beginning byte of a string to be an opening quote, but we got a "%s"`, string(b)))
	}
	str := strings.Builder{}
	// consume the string literal
	// This loop does not in any way honor escaped quotes.
	for b, _, err = r.ReadRune(); err == nil && b != '"'; b, _, err = r.ReadRune() {
		str.WriteRune(b) // always returns a nil error
	}
	if err != nil {
		return "", errors.Wrap(err, "failure occurred while consuming a string literal")
	}
	// consume up to the , that delimits struct literal fields.
	// This does not in any way honor the final field omitting this comma.
	b, err = consumeWhiteSpace(r)
	if err != nil {
		return "", errors.Wrap(err, "failed to consume the leading whitespace before the string field delimiter (comma)")
	}
	if b != ',' {
		return "", errors.New(fmt.Sprintf(`expected the final byte of a string field to be a comma, but we got a "%s"`, string(b)))
	}
	return str.String(), nil
}

// consumes all whitespace up to the next non-whitespace run and returns that rune.
func consumeWhiteSpace(r io.RuneReader) (rune, error) {
	var b rune
	var err error
	for b, _, err = r.ReadRune(); err == nil; b, _, err = r.ReadRune() {
		switch b {
		case ' ', '\n', '\t', '\r':
		default:
			return b, err
		}
	}
	return b, err
}

type Response struct {
	Error   *string
	EVInfos []*EVInfo
}

func nightlyHandler(w http.ResponseWriter, r *http.Request) {
	corehandler(w, r, nightly)
}

func betaHandler(w http.ResponseWriter, r *http.Request) {
	corehandler(w, r, beta)
}

func releaseHandler(w http.ResponseWriter, r *http.Request) {
	corehandler(w, r, release)
}

func givenHandler(w http.ResponseWriter, r *http.Request) {
	u, ok := r.URL.Query()["url"]
	if !ok {
		w.WriteHeader(400)
		_, err := w.Write([]byte("'url' is a required query parameter"))
		if err != nil {
			log.Println(err)
		}
		return
	}
	if len(u) == 0 {
		w.WriteHeader(400)
		_, err := w.Write([]byte("'url' query parameter may not be empty"))
		if err != nil {
			log.Println(err)
		}
		return
	}
	target, err := url.QueryUnescape(u[0])
	if err != nil {
		w.WriteHeader(400)
		_, err = w.Write([]byte(fmt.Sprintf("failed to decode `url` query parameter, err: %s", err)))
		if err != nil {
			log.Println(err)
		}
		return
	}
	corehandler(w, r, target)
}

func corehandler(w http.ResponseWriter, r *http.Request, target string) {
	resp := Response{}
	code := 500
	defer func() {
		w.WriteHeader(code)
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(resp); err != nil {
			log.Print(err)
		}
	}()
	file, err := get(target)
	if err != nil {
		code = 500
		errStr := err.Error()
		resp.Error = &errStr
		return
	}
	kEVInfos, err := extract(file)
	if err != nil {
		code = 500
		errStr := err.Error()
		resp.Error = &errStr
		return
	}
	resp.EVInfos = kEVInfos
}

func main() {
	http.HandleFunc("/nightly", nightlyHandler)
	http.HandleFunc("/beta", betaHandler)
	http.HandleFunc("/release", releaseHandler)
	http.HandleFunc("/", givenHandler)
	port := Port()
	addr := BindingAddress()
	if err := http.ListenAndServe(addr+":"+port, nil); err != nil {
		log.Panicln(err)
	}
}

func Port() string {
	return fmt.Sprintf("%d", parseIntFromEnvOrDie("PORT", 8080))
}

func BindingAddress() string {
	switch addr := os.Getenv("ADDR"); addr {
	case "":
		return "0.0.0.0"
	default:
		_, _, err := net.ParseCIDR(addr)
		if err != nil {
			panic("failed to parse the provided ADDR to a valid CIDR")
		}
		return addr
	}
}

func parseIntFromEnvOrDie(key string, defaultVal int) int {
	switch val := os.Getenv(key); val {
	case "":
		return defaultVal
	default:
		i, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			fmt.Printf("%s (%s) could not be parsed to an integer", val, key)
			os.Exit(1)
		}
		return int(i)
	}
}
