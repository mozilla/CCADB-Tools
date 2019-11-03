/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package x509lint

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"reflect"
)

type X509Lint struct {
	Errors   []string
	Warnings []string
	Info     []string
	CmdError *string
}

type certType int

const (
	subscriber certType = iota
	intermediate
	ca
)

var certTypeToStr = map[certType]string{
	subscriber:   "subscriber",
	intermediate: "intermediate",
	ca:           "ca",
}

func LintChain(certificates []*x509.Certificate) ([]X509Lint, error) {
	results := make([]X509Lint, len(certificates))
	for i, cert := range certificates {
		var ct certType
		switch {
		case i == 0:
			ct = subscriber
		case reflect.DeepEqual(cert.Subject, cert.Issuer):
			ct = ca
		default:
			ct = intermediate
		}
		l, err := Lint(cert, ct)
		if err != nil {
			return results, err
		}
		results[i] = l
	}
	return results, nil
}

func Lint(certificate *x509.Certificate, ctype certType) (X509Lint, error) {
	result := NewX509Lint()
	f, err := ioutil.TempFile("", "x509lint")
	if err != nil {
		return result, err
	}
	defer func() {
		if err := os.Remove(f.Name()); err != nil {
			log.Println(err)
		}
	}()
	err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err != nil {
		return result, err
	}
	err = f.Close()
	if err != nil {
		return result, err
	}
	cmd := exec.Command("x509lint", f.Name(), certTypeToStr[ctype])
	stdout := bytes.NewBuffer([]byte{})
	stderr := bytes.NewBuffer([]byte{})
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmderr := cmd.Run()
	output, err := ioutil.ReadAll(stdout)
	if err != nil {
		return result, err
	}
	errors, err := ioutil.ReadAll(stderr)
	if err != nil {
		return result, err
	}
	if cmderr != nil {
		errStr := fmt.Sprintf("%s, stderr: %s, stdout: %s, cmd: %s %s %s", cmderr, string(errors), string(output), "x509lint", f.Name(), certTypeToStr[ctype])
		result.CmdError = &errStr
		// This has the slight distinction of being an error
		// from x509lint itself rather than from, say,
		// the filesystem or shell failing.
		return result, nil
	}
	parseOutput(output, &result)
	return result, nil
}

func NewX509Lint() X509Lint {
	return X509Lint{
		Errors:   make([]string, 0),
		Warnings: make([]string, 0),
		Info:     make([]string, 0),
		CmdError: nil,
	}
}

func parseOutput(output []byte, result *X509Lint) {
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		if bytes.HasPrefix(line, []byte("E: ")) {
			result.Errors = append(result.Errors, string(line[3:]))
		} else if bytes.HasPrefix(line, []byte("W: ")) {
			result.Warnings = append(result.Warnings, string(line[3:]))
		} else if bytes.HasPrefix(line, []byte("I: ")) {
			result.Info = append(result.Info, string(line[3:]))
		} else {
			log.Printf(`unexpected x509Lint output: "{}"`, string(output))
		}
	}
}
