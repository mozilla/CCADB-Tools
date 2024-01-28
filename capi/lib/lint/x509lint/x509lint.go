/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package x509lint

import (
	"bytes"
	"crypto/x509"
	go_x509lint "github.com/crtsh/go-x509lint"
	"log"
	"reflect"
	"sync"
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

// go_x509lint.Init() and go_x509lint.Finish() both mutate global state.
//
// Concurrent read/writes MAY be safe for some roundabout reason that I cannot see,
// but given that there are no docs on the matter it seems prudent to simply
// lock the library for a given certificate check.
var x509LintLock = sync.Mutex{}

func Lint(certificate *x509.Certificate, ctype certType) (X509Lint, error) {
	x509LintLock.Lock()
	defer x509LintLock.Unlock()
	go_x509lint.Init()
	defer go_x509lint.Finish()
	go_x509lint.Init()
	got := go_x509lint.Check(certificate.Raw, int(ctype))
	result := NewX509Lint()
	parseOutput([]byte(got), &result)
	return result, nil
}

func NewX509Lint() X509Lint {
	return X509Lint{
		Errors:   make([]string, 0),
		Warnings: make([]string, 0),
		Info:     make([]string, 0),
	}
}

func parseOutput(output []byte, result *X509Lint) {
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		if line == nil || len(line) == 0 {
			continue
		}
		if bytes.HasPrefix(line, []byte("E: ")) {
			if bytes.Contains(line, []byte("Fails decoding the characterset")) {
				// @TODO We currently have no notion as why this happens, so we are ignoring it for now.
				continue
			}
			result.Errors = append(result.Errors, string(line[3:]))
		} else if bytes.HasPrefix(line, []byte("W: ")) {
			result.Warnings = append(result.Warnings, string(line[3:]))
		} else if bytes.HasPrefix(line, []byte("I: ")) {
			result.Info = append(result.Info, string(line[3:]))
		} else {
			log.Printf(`unexpected x509Lint output: "%s"`, string(output))
		}
	}
}
