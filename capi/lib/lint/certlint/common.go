package certlint

import (
	"bytes"
	"crypto/x509"
	"io/ioutil"
	"os"
	"os/exec"
)

const LIB = `/opt/certlint/lib/:/opt/certlint/ext`
const CERTLINT = `/opt/certlint/bin/certlint`
const CABLINT = `/opt/certlint/bin/cablint`

type Certlint struct {
	Certlint certlint
	Cablint certlint
}

func LintCerts(certificates []*x509.Certificate) []Certlint {
	lints := make([]Certlint, len(certificates))
	for i, cert := range certificates {
		lints[i] = Lint(cert)
	}
	return lints
}

func Lint(certificate *x509.Certificate) Certlint {
	var result Certlint
	f, err := ioutil.TempFile("", "certlint")
	if err != nil {
		panic(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	err = ioutil.WriteFile(f.Name(), certificate.Raw, 066)
	if err != nil {
		panic(err)
	}
	result.Certlint = lint(f.Name(), CERTLINT)
	result.Cablint = lint(f.Name(), CABLINT)
	return result
}

type certlint struct {
	Bug []string
	Info []string
	Notices []string
	Warnings []string
	Errors []string
	Fatal []string
	CmdError *string
}

func NewCertlint() certlint {
	return certlint{
		Bug:  make([]string, 0),
		Info:    make([]string, 0),
		Notices:  make([]string, 0),
		Warnings: make([]string, 0),
		Errors:   make([]string, 0),
		Fatal:   make([]string, 0),
		CmdError:nil,
	}
}

func lint(fname, tool string) certlint {
	result := NewCertlint()
	cmd := exec.Command("ruby", "-I", LIB, tool, fname)
	stdout := bytes.NewBuffer([]byte{})
	stderr := bytes.NewBuffer([]byte{})
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if err != nil {
		errStr := err.Error()
		result.CmdError = &errStr
		return result
	}
	output, err := ioutil.ReadAll(stdout)
	if err != nil {
		errStr := err.Error()
		result.CmdError = &errStr
		return result
	}
	errors, err := ioutil.ReadAll(stderr)
	if err != nil {
		errStr := err.Error()
		result.CmdError = &errStr
		return result
	}
	if string(errors) != "" {
		errStr := string(errors)
		result.CmdError = &errStr
		return result
	}
	parseOutput(output, &result)
	return result
}

//
    //B: Bug. Your certificate has a feature not handled by certlint.
    //I: Information. These are purely informational; no action is needed.
    //N: Notice. These are items known to cause issues with one or more implementations of certificate processing but are not errors according to the standard.
    //W: Warning. These are issues where a standard recommends differently but the standard uses terms such as "SHOULD" or "MAY".
    //E: Error. These are issues where the certificate is not compliant with the standard.
    //F: Fatal Error. These errors are fatal to the checks and prevent most further checks from being executed. These are extremely bad errors.

func parseOutput(output []byte, result *certlint) {
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		if bytes.HasPrefix(line, []byte("B: ")) {
			result.Bug = append(result.Bug, string(line[3:]))
		} else if bytes.HasPrefix(line, []byte("I: ")) {
			result.Info = append(result.Info, string(line[3:]))
		} else if bytes.HasPrefix(line, []byte("N: ")) {
			result.Notices = append(result.Notices, string(line[3:]))
		} else if bytes.HasPrefix(line, []byte("W: ")) {
			result.Warnings = append(result.Warnings, string(line[3:]))
		} else if bytes.HasPrefix(line, []byte("E: ")) {
			result.Errors = append(result.Errors, string(line[3:]))
		} else if bytes.HasPrefix(line, []byte("F: ")) {
			result.Fatal = append(result.Fatal, string(line[3:]))
		}
	}
}