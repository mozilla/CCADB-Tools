/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main // import "github.com/mozilla/CCADB-Tools/crlVerification"
import (
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"github.com/mozilla/CCADB-Tools/crlVerification/utils"
	"github.com/pkg/errors"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

type Input struct {
	Crl    []string
	Serial *big.Int
	Date   time.Time
	Reason utils.RevocationReason
	errs   []error
}

func NewInput() Input {
	return Input{
		Crl:    make([]string, 0),
		Serial: nil,
		Date:   time.Time{},
		Reason: utils.NOT_GIVEN,
		errs:   make([]error, 0),
	}
}

func (i *Input) UnmarshalJSON(data []byte) error {
	intermediate := make(map[string]interface{})
	err := json.Unmarshal(data, &intermediate)
	if err != nil {
		i.errs = append(i.errs, err)
		return nil
	}
	if c, ok := intermediate["crl"]; ok {
		switch t := c.(type) {
		case []interface{}:
			for _, crlInterface := range t {
				switch crl := crlInterface.(type) {
				case string:
					i.Crl = append(i.Crl, crl)
				default:
					i.errs = append(i.errs, errors.New(fmt.Sprintf(`unexpected type for "crl", got %T from value "%v"`, crl, crl)))
				}
			}
		case string:
			// The old interface was built for
			// only one CRL, so let's honor that just in case
			i.Crl = append(i.Crl, t)
		case nil:
			// The old interface allowed for a null entry
			// so let's leave that in place by leaving the array empty.
		default:
			i.errs = append(i.errs, errors.New(fmt.Sprintf(`unexpected type for "crl", got %T from value "%v"`, t, t)))
		}
	}
	if s, ok := intermediate["serial"]; ok {
		switch t := s.(type) {
		case string:
			serial, err := utils.BigIntFromHexString(t)
			if err != nil {
				i.errs = append(i.errs, err)
			} else {
				i.Serial = serial
			}
		default:
			i.errs = append(i.errs, errors.New(fmt.Sprintf(`unexpected type for "serial", got %T from value "%v"`, t, t)))
		}
	} else {
		i.errs = append(i.errs, errors.New(`"serial" is a required field`))
	}
	if d, ok := intermediate["revocationDate"]; ok {
		switch t := d.(type) {
		case string:
			date, err := utils.TimeFromString(t)
			if err != nil {
				i.errs = append(i.errs, err)
			} else {
				i.Date = date
			}
		default:
			i.errs = append(i.errs, errors.New(fmt.Sprintf(`unexpected type for "revocationData", got %T from value "%v"`, t, t)))
		}
	} else {
		i.errs = append(i.errs, errors.New(`"revocationDate" is a required field`))
	}
	if r, ok := intermediate["revocationReason"]; ok {
		switch t := r.(type) {
		case string:
			reason, err := utils.FromString(&t)
			if err != nil {
				i.errs = append(i.errs, err)
			} else {
				i.Reason = reason
			}
		default:
			i.errs = append(i.errs, errors.New(fmt.Sprintf(`unexpected type for "revocationReason", got %T from value "%v"`, t, t)))
		}
	} else {
		i.Reason = utils.NOT_GIVEN
	}
	return nil
}

type Result string

const (
	PASS Result = "PASS"
	FAIL Result = "FAIL"
)

type Return struct {
	Result Result
	Errors []error
}

func (r Return) MarshalJSON() ([]byte, error) {
	result := r.Result
	errs := make([]string, len(r.Errors))
	for i := 0; i < len(errs); i++ {
		errs[i] = r.Errors[i].Error()
	}
	return json.Marshal(map[string]interface{}{
		"Result": result,
		"Errors": errs,
	})
}

func NewReturn() Return {
	return Return{
		Result: FAIL,
		Errors: make([]error, 0),
	}
}

func Validate(i Input) Return {
	if len(i.Crl) == 0 {
		ret := NewReturn()
		ret.Errors = append(ret.Errors, utils.CRLNotGiven{})
		return ret
	}
	allErrors := make([]error, 0)
	for _, c := range i.Crl {
		crl, err := utils.CRLFromURL(c)
		switch err == nil {
		case true:
			return validate(i, crl)
		case false:
			log.Printf("failed to retrieve CRL from %s, err: %s", c, err)
			allErrors = append(allErrors, err)
		}
	}
	ret := NewReturn()
	ret.Errors = append(ret.Errors, allErrors...)
	return ret
}

func validate(i Input, crl *pkix.CertificateList) Return {
	ret := NewReturn()
	cert, err := utils.FindSerial(crl, i.Serial)
	if err != nil {
		ret.Errors = append(ret.Errors, err)
		return ret
	}
	if err = utils.ValidateRevocationDate(cert, i.Date); err != nil {
		ret.Errors = append(ret.Errors, err)
	}
	if err = utils.ValidateRevocationReason(cert, i.Reason); err != nil {
		ret.Errors = append(ret.Errors, err)
	}
	if len(ret.Errors) == 0 {
		ret.Result = PASS
	}
	return ret
}

func endpoint(resp http.ResponseWriter, req *http.Request) {
	ret := NewReturn()
	code := 200
	defer func() {
		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(code)
		encoder := json.NewEncoder(resp)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(&ret); err != nil {
			fmt.Println(err)
		}
	}()
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		code = 500
		resp.WriteHeader(500)
		ret = Return{
			Result: FAIL,
			Errors: []error{err},
		}
		return
	}
	_ = req.Body.Close()
	i := NewInput()
	err = json.Unmarshal(body, &i)
	if err != nil {
		code = 500
		ret = Return{
			Result: FAIL,
			Errors: []error{err},
		}
		return
	}
	if len(i.errs) != 0 {
		code = 400
		ret = Return{
			Result: FAIL,
			Errors: i.errs,
		}
		return
	}
	code = 200
	ret = Validate(i)
}

func main() {
	http.HandleFunc("/", endpoint)
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
