/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package x509lint

import (
	"crypto/x509"
	go_x509lint "github.com/crtsh/go-x509lint"
	"log"
	"reflect"
	"strings"
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
		results[i] = Lint(cert, ct)
	}
	return results, nil
}

// go_x509lint.Init() and go_x509lint.Finish() both mutate global state.
//
// Concurrent read/writes MAY be safe for some roundabout reason that I cannot see,
// but given that there are no docs on the matter it seems prudent to simply
// lock the library for a given certificate check.
var x509LintLock = sync.Mutex{}

func Lint(certificate *x509.Certificate, ctype certType) X509Lint {
	x509LintLock.Lock()
	defer x509LintLock.Unlock()
	go_x509lint.Init()
	defer go_x509lint.Finish()
	got := go_x509lint.Check(certificate.Raw, int(ctype))
	return parseOutput(got)
}

func NewX509Lint() X509Lint {
	return X509Lint{
		Errors:   make([]string, 0),
		Warnings: make([]string, 0),
		Info:     make([]string, 0),
	}
}

func parseOutput(output string) X509Lint {
	result := NewX509Lint()
	for _, line := range strings.Split(output, "\n") {
		if len(line) == 0 {
			continue
		}
		if strings.HasPrefix(line, "E: ") {
			if strings.Contains(line, "Fails decoding the characterset") {
				// @TODO We currently have no notion as why this happens, so we are ignoring it for now.
				continue
			}
			result.Errors = append(result.Errors, line[3:])
		} else if strings.HasPrefix(line, "W: ") {
			result.Warnings = append(result.Warnings, line[3:])
		} else if strings.HasPrefix(line, "I: ") {
			result.Info = append(result.Info, line[3:])
		} else {
			log.Printf(`unexpected x509Lint output: "%s"`, line)
		}
	}
	return result
}
